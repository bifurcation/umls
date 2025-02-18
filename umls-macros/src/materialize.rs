use quote::quote;
use syn::*;

pub fn derive(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let name = input.ident;

    if input.generics.type_params().count() > 0 {
        panic!("derive(Materialize) is not compatible with generic parameters");
    }

    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let expanded = quote! {
        impl #impl_generics Materialize for #name #ty_generics #where_clause {
            type Storage = Vec<u8, { #name::MAX_SIZE }>;
        }
    };

    proc_macro::TokenStream::from(expanded)
}
