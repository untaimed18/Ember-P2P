//! The command attribute and the command table, so one list of commands
//! serves both the desktop app, where Tauri calls them, and `emberd`, where
//! its HTTP interface does.
//!
//! `#[ember_macros::command]` puts `#[tauri::command]` on a function in the
//! desktop build. In the server build it adds, beside the function, a
//! dispatcher that reads the arguments from a JSON object under the keys
//! Tauri would use, passes the state, app handle and window the server has,
//! and serializes what the function returns as Tauri would.
//! `#[ember_macros::command(desktop)]` marks a command only the desktop app
//! has: it exists in the desktop build alone.
//!
//! `ember_macros::command_table!` takes every command once and gives the
//! desktop build `desktop_handler!` (Tauri's `generate_handler!` over all of
//! them) and the server build `SERVER_COMMANDS`, the dispatchers by name.

use heck::ToLowerCamelCase;
use proc_macro::TokenStream;
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::{format_ident, quote};
use syn::ext::IdentExt;
use syn::parse::{Parse, ParseStream};
use syn::punctuated::Punctuated;
use syn::{
    parse_macro_input, Error, FnArg, GenericArgument, Ident, ItemFn, Pat, Path, PathArguments, Token, Type,
};

#[proc_macro_attribute]
pub fn command(attr: TokenStream, item: TokenStream) -> TokenStream {
    let only = match parse_command_attr(attr) {
        Ok(only) => only,
        Err(e) => return e.to_compile_error().into(),
    };
    let function = parse_macro_input!(item as ItemFn);
    if only == Only::Desktop {
        return quote! {
            #[cfg(feature = "desktop")]
            #[::tauri::command]
            #function
        }
        .into();
    }
    let dispatcher = match server_dispatcher(&function) {
        Ok(dispatcher) => dispatcher,
        Err(e) => return e.to_compile_error().into(),
    };
    if only == Only::Server {
        return quote! {
            #[cfg(feature = "server")]
            #function
            #dispatcher
        }
        .into();
    }
    quote! {
        #[cfg_attr(feature = "desktop", ::tauri::command)]
        #function
        #dispatcher
    }
    .into()
}

/// Which builds a command is in.
#[derive(PartialEq)]
enum Only {
    Both,
    Desktop,
    Server,
}

fn parse_command_attr(attr: TokenStream) -> syn::Result<Only> {
    if attr.is_empty() {
        return Ok(Only::Both);
    }
    let ident: Ident = syn::parse(attr)?;
    match ident.to_string().as_str() {
        "desktop" => Ok(Only::Desktop),
        "server" => Ok(Only::Server),
        _ => Err(Error::new(ident.span(), "expected `desktop`, `server` or nothing")),
    }
}

/// What a command parameter is, as Tauri would fill it.
enum Param<'a> {
    State(&'a Type),
    AppHandle,
    Window,
    Value { ty: &'a Type, key: String },
}

/// The name of the dispatcher `emberd` calls for `command`.
fn dispatcher_ident(command: &Ident) -> Ident {
    format_ident!("__ember_server_{}", command.unraw())
}

fn server_dispatcher(function: &ItemFn) -> syn::Result<TokenStream2> {
    let sig = &function.sig;
    if !sig.generics.params.is_empty() {
        return Err(Error::new_spanned(
            &sig.generics,
            "emberd cannot call a generic command; mark it #[ember_macros::command(desktop)]",
        ));
    }
    let name = &sig.ident;
    let dispatcher = dispatcher_ident(name);
    let command_name = name.unraw().to_string();
    let mut prelude = Vec::new();
    let mut call_args = Vec::new();
    for (index, input) in sig.inputs.iter().enumerate() {
        let FnArg::Typed(typed) = input else {
            return Err(Error::new_spanned(input, "a command cannot take self"));
        };
        let var = Ident::new(&format!("__ember_arg_{index}"), Span::call_site());
        match classify(&typed.ty, &typed.pat)? {
            Param::State(inner) => prelude.push(quote!(let #var = __ember_invoke.state::<#inner>()?;)),
            Param::AppHandle => prelude.push(quote!(let #var = __ember_invoke.app_handle();)),
            Param::Window => prelude.push(quote!(let #var = __ember_invoke.window();)),
            Param::Value { ty, key } => {
                prelude.push(quote!(let #var: #ty = __ember_invoke.arg(#command_name, #key)?;));
            }
        }
        call_args.push(var);
    }
    let call = if sig.asyncness.is_some() {
        quote!(#name(#(#call_args),*).await)
    } else {
        // A Tauri command without `async` runs off the async runtime; one
        // that blocks must not hold an async worker either.
        quote!(::tokio::task::block_in_place(move || #name(#(#call_args),*)))
    };
    Ok(quote! {
        #[cfg(feature = "server")]
        #[doc(hidden)]
        #[allow(non_snake_case, clippy::all, unused_mut)]
        pub(crate) fn #dispatcher(__ember_invoke: crate::host::Invoke) -> crate::host::InvokeFuture {
            ::std::boxed::Box::pin(async move {
                #(#prelude)*
                let __ember_result = #call;
                #[allow(unused_imports)]
                use crate::host::{InvokePlain as _, InvokeResult as _};
                (&crate::host::InvokeTag(__ember_result)).invoke_value()
            })
        }
    })
}

fn classify<'a>(ty: &'a Type, pat: &Pat) -> syn::Result<Param<'a>> {
    if let Type::Path(path) = ty {
        if let Some(last) = path.path.segments.last() {
            match last.ident.to_string().as_str() {
                "State" => return state_inner(&last.arguments).map(Param::State),
                "AppHandle" => return Ok(Param::AppHandle),
                "WebviewWindow" | "Window" => return Ok(Param::Window),
                "Channel" | "Request" | "Webview" => {
                    return Err(Error::new_spanned(
                        ty,
                        "emberd has no equivalent for this parameter; mark the command #[ember_macros::command(desktop)]",
                    ));
                }
                _ => {}
            }
        }
    }
    Ok(Param::Value { ty, key: argument_key(pat)? })
}

/// The `T` of `State<'_, T>`.
fn state_inner(arguments: &PathArguments) -> syn::Result<&Type> {
    if let PathArguments::AngleBracketed(args) = arguments {
        for arg in &args.args {
            if let GenericArgument::Type(ty) = arg {
                return Ok(ty);
            }
        }
    }
    Err(Error::new_spanned(arguments, "expected State<'_, T>"))
}

/// The JSON key Tauri reads an argument from: its name, without `r#`, in
/// lower camel case (`tauri-macros`' `parse_arg`).
fn argument_key(pat: &Pat) -> syn::Result<String> {
    let name = match pat {
        Pat::Ident(ident) => ident.ident.unraw().to_string(),
        Pat::Wild(_) => String::new(),
        other => {
            return Err(Error::new_spanned(other, "only named or wildcard command arguments are supported"));
        }
    };
    Ok(name.to_lower_camel_case())
}

struct TableEntry {
    desktop_only: bool,
    server_only: bool,
    harness: bool,
    path: Path,
}

impl Parse for TableEntry {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let mut desktop_only = false;
        let mut server_only = false;
        let mut harness = false;
        while input.peek(Token![#]) {
            input.parse::<Token![#]>()?;
            let content;
            syn::bracketed!(content in input);
            let marker: Ident = content.parse()?;
            match marker.to_string().as_str() {
                "desktop" => desktop_only = true,
                "server" => server_only = true,
                "harness" => harness = true,
                _ => return Err(Error::new(marker.span(), "expected #[desktop], #[server] or #[harness]")),
            }
        }
        Ok(TableEntry { desktop_only, server_only, harness, path: input.parse()? })
    }
}

struct Table {
    entries: Punctuated<TableEntry, Token![,]>,
}

impl Parse for Table {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        Ok(Table { entries: Punctuated::parse_terminated(input)? })
    }
}

/// The command's name, the last segment of its path.
fn command_name(path: &Path) -> syn::Result<&Ident> {
    path.segments
        .last()
        .map(|segment| &segment.ident)
        .ok_or_else(|| Error::new_spanned(path, "expected a path to a command"))
}

#[proc_macro]
pub fn command_table(input: TokenStream) -> TokenStream {
    let table = parse_macro_input!(input as Table);
    match expand_table(&table) {
        Ok(tokens) => tokens.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

fn expand_table(table: &Table) -> syn::Result<TokenStream2> {
    let mut seen = std::collections::BTreeSet::new();
    let mut app = Vec::new();
    let mut harness = Vec::new();
    let mut server = Vec::new();
    let mut desktop_only = Vec::new();
    for entry in &table.entries {
        let name = command_name(&entry.path)?;
        let name_text = name.unraw().to_string();
        if !seen.insert(name_text.clone()) {
            return Err(Error::new_spanned(&entry.path, format!("`{name_text}` is in the command table twice")));
        }
        let path = &entry.path;
        if entry.harness {
            harness.push(quote!(crate::#path));
            continue;
        }
        if !entry.server_only {
            app.push(quote!(crate::#path));
        }
        if entry.desktop_only {
            desktop_only.push(name_text);
            continue;
        }
        let mut dispatcher = entry.path.clone();
        if let Some(last) = dispatcher.segments.last_mut() {
            last.ident = dispatcher_ident(name);
        }
        server.push(quote!((#name_text, crate::#dispatcher as crate::host::Handler)));
    }
    Ok(quote! {
        /// Tauri's handler over every command; `harness` adds the ones a
        /// debug build carries for the multi-node harness.
        #[cfg(feature = "desktop")]
        macro_rules! desktop_handler {
            () => { ::tauri::generate_handler![#(#app),*] };
            (harness) => { ::tauri::generate_handler![#(#app,)* #(#harness),*] };
        }
        #[cfg(feature = "desktop")]
        pub(crate) use desktop_handler;

        /// What `emberd` can call, by name.
        #[cfg(feature = "server")]
        pub(crate) static SERVER_COMMANDS: &[(&str, crate::host::Handler)] = &[#(#server),*];

        /// Commands the desktop app has and `emberd` does not.
        #[allow(dead_code)]
        pub(crate) const DESKTOP_ONLY_COMMANDS: &[&str] = &[#(#desktop_only),*];
    })
}
