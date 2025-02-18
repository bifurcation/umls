use proc_macro2::TokenStream;
use quote::{quote, quote_spanned};
use syn::spanned::Spanned;
use syn::*;

use crate::enum_discriminant;

pub fn derive(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let name = input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let max_size = max_size(&input.attrs, &input.data);
    let serialize_body = serialize(&input.attrs, &input.data);

    let expanded = quote! {
        impl #impl_generics Serialize for #name #ty_generics #where_clause {
            const MAX_SIZE: usize = #max_size;

            fn serialize(&self, writer: &mut impl Write) -> Result<()> {
                #serialize_body
                Ok(())
            }
        }
    };

    proc_macro::TokenStream::from(expanded)
}

fn total_size(fields: &Fields) -> TokenStream {
    match fields {
        Fields::Named(ref fields) => {
            let recurse = fields.named.iter().map(|f| {
                let ty = &f.ty;
                quote_spanned! {f.span()=>
                    <#ty as Serialize>::MAX_SIZE
                }
            });
            quote! {
                0 #(+ #recurse)*
            }
        }
        Fields::Unnamed(ref fields) => {
            let recurse = fields.unnamed.iter().map(|f| {
                let ty = &f.ty;
                quote_spanned! {f.span()=>
                    <#ty as Serialize>::MAX_SIZE
                }
            });
            quote! {
                0 #(+ #recurse)*
            }
        }
        Fields::Unit => {
            quote!(0)
        }
    }
}

// Generate an expression to compute the maximum serialized size of an object.
fn max_size(attrs: &[Attribute], data: &Data) -> TokenStream {
    match *data {
        Data::Struct(ref data) => total_size(&data.fields),

        Data::Enum(ref data) => {
            let d_ty = enum_discriminant::ty(attrs).unwrap();
            let d_size = quote! { <#d_ty as Serialize>::MAX_SIZE };

            let mut max = quote! { 0 };
            for variant in data.variants.iter() {
                let variant_size = total_size(&variant.fields);
                max = quote! { if #max > #variant_size { #max } else { #variant_size } };
            }
            quote! { #d_size + #max }
        }

        // Unions are not supported
        Data::Union(_) => unimplemented!(),
    }
}

fn serialize(attrs: &[Attribute], data: &Data) -> TokenStream {
    match *data {
        Data::Struct(ref data) => match data.fields {
            Fields::Named(ref fields) => {
                let recurse = fields.named.iter().map(|f| {
                    let ident = &f.ident;
                    quote_spanned! {f.span()=>
                        self.#ident.serialize(writer)?;
                    }
                });
                quote! { #(#recurse)* }
            }
            Fields::Unnamed(ref fields) => {
                let recurse = fields.unnamed.iter().enumerate().map(|(i, f)| {
                    let index = Index::from(i);
                    quote_spanned! {f.span()=>
                        self.#index.serialize(writer)?;
                    }
                });
                quote! { #(#recurse)* }
            }
            Fields::Unit => {
                quote! {}
            }
        },

        Data::Enum(ref data) => {
            let d_ty = enum_discriminant::ty(attrs).unwrap();
            let recurse = data.variants.iter().map(|v| {
                let ident = &v.ident;
                let d_val = enum_discriminant::value(&v.attrs);

                // XXX(RLB): Pretty sure this fails if the enum has a structure other than a
                // single, unnamed fields.  But I'm not sure we care about those cases.
                quote! {
                    Self::#ident(x) => {
                        <#d_ty as Serialize>::serialize(&#d_val, writer)?;
                        x.serialize(writer)?;
                    },
                }
            });

            quote! {
                match self {
                    #(#recurse)*
                }
            }
        }

        // Unions are not supported
        Data::Union(_) => unimplemented!(),
    }
}
