use proc_macro2::TokenStream;
use quote::{quote, quote_spanned};
use syn::spanned::Spanned;
use syn::*;

use crate::enum_discriminant;

pub fn derive(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let name = input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let deserialize_body = deserialize(&input.attrs, &input.data);

    let expanded = quote! {
        impl #impl_generics Deserialize for #name #ty_generics #where_clause {
            fn deserialize(reader: &mut impl Read) -> Result<Self> {
                #deserialize_body
            }
        }
    };

    proc_macro::TokenStream::from(expanded)
}

fn deserialize(attrs: &[Attribute], data: &Data) -> TokenStream {
    match *data {
        Data::Struct(ref data) => match data.fields {
            Fields::Named(ref fields) => {
                let recurse = fields.named.iter().map(|f| {
                    let ty = &f.ty;
                    let ident = &f.ident;
                    quote_spanned! {f.span()=>
                        #ident: <#ty as Deserialize>::deserialize(reader)?,
                    }
                });
                quote! { Ok(Self { #(#recurse)* }) }
            }
            Fields::Unnamed(ref fields) => {
                let recurse = fields.unnamed.iter().map(|f| {
                    let ty = &f.ty;
                    quote_spanned! {f.span()=>
                        <#ty as Deserialize>::deserialize(reader)?,
                    }
                });
                quote! { Ok(Self( #(#recurse)* )) }
            }
            Fields::Unit => {
                quote! { Ok(Self) }
            }
        },

        Data::Enum(ref data) => {
            let recurse = data.variants.iter().map(|v| {
                let ident = &v.ident;
                let d_val = enum_discriminant::value(&v.attrs);

                let Fields::Unnamed(fields) = &v.fields else {
                    panic!("Invalid enum variant: Must be a tuple");
                };

                let Some(field) = fields.unnamed.iter().next() else {
                    panic!("Invalid enum variant: Must be a tuple with at least one element");
                };

                let ty = &field.ty;

                quote! {
                    #d_val => {
                        let val = <#ty as Deserialize>::deserialize(reader)?;
                        Ok(Self::#ident(val))
                    }
                }
            });

            let d_ty = enum_discriminant::ty(attrs).unwrap();
            quote! {
                let disc = <#d_ty as Deserialize>::deserialize(reader)?;
                match disc {
                    #(#recurse)*,
                    _ => Err(Error("Invalid encoding")),
                }
            }
        }

        // Unions are not supported
        Data::Union(_) => unimplemented!(),
    }
}
