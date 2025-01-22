use proc_macro2::{Span, TokenStream};
use quote::{quote, quote_spanned};
use syn::spanned::Spanned;
use syn::*;

#[proc_macro_derive(Serialize, attributes(discriminant))]
pub fn derive_serialize(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    // Parse the input tokens into a syntax tree.
    let input = parse_macro_input!(input as DeriveInput);

    // Used in the quasi-quotation below as `#name`.
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

#[proc_macro_derive(Deserialize, attributes(discriminant))]
pub fn derive_deserialize(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
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

#[proc_macro_derive(Signed, attributes(label))]
pub fn derive_signed(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let name = input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    // The ToBeSigned type is the type of the "tbs" field
    let Data::Struct(data) = &input.data else {
        panic!("Signed structures must be structs");
    };

    let Fields::Named(fields) = &data.fields else {
        panic!("Signed structures must have named fields");
    };

    let tbs_ident = Some(Ident::new("tbs", Span::call_site()));
    let Some(tbs) = fields.named.iter().find(|f| f.ident == tbs_ident) else {
        panic!("Signed structures must have a 'tbs' field");
    };

    let to_be_signed = &tbs.ty;

    // The signature label is provided by an attribute
    let mut attrs = input.attrs.iter().filter_map(|attr| match &attr.meta {
        Meta::NameValue(MetaNameValue { path, value, .. }) => {
            if !path.is_ident("label") {
                return None;
            }

            let Expr::Lit(ExprLit {
                lit: Lit::ByteStr(lit_str),
                ..
            }) = value
            else {
                return None;
            };

            Some(lit_str)
        }
        _ => None,
    });

    let Some(label) = attrs.next() else {
        panic!("Signed structures must have a 'label' attribute");
    };

    // Produce the implementation
    let expanded = quote! {
        impl #impl_generics Signed #ty_generics for #name #ty_generics #where_clause {
            type ToBeSigned = #to_be_signed;
            const LABEL: &[u8] = #label;

            fn new(tbs: Self::ToBeSigned, signature: C::Signature) -> Self {
                Self { tbs, signature }
            }

            fn tbs(&self) -> &Self::ToBeSigned {
                &self.tbs
            }
            fn signature(&self) -> &C::Signature {
                &self.signature
            }
        }
    };

    proc_macro::TokenStream::from(expanded)
}

// For structs, expands to an expression like:
//
//     0 + A::MAX_SIZE + B::MAX_SIZE
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

fn enum_discriminant_type(attrs: &[Attribute]) -> Option<Type> {
    attrs
        .iter()
        .filter_map(|attr| match &attr.meta {
            Meta::NameValue(MetaNameValue { path, value, .. }) => {
                if !path.is_ident("discriminant") {
                    return None;
                }

                let Expr::Lit(ExprLit {
                    lit: Lit::Str(lit_str),
                    ..
                }) = value
                else {
                    return None;
                };

                Some(lit_str.parse().unwrap())
            }
            _ => None,
        })
        .next()
}

fn enum_discriminant_value(attrs: &[Attribute]) -> Option<Expr> {
    attrs
        .iter()
        .filter_map(|attr| match &attr.meta {
            Meta::NameValue(MetaNameValue { path, value, .. }) => {
                if !path.is_ident("discriminant") {
                    return None;
                }

                let Expr::Lit(ExprLit {
                    lit: Lit::Str(lit_str),
                    ..
                }) = value
                else {
                    return None;
                };

                Some(lit_str.parse().unwrap())
            }
            _ => None,
        })
        .next()
}

// Generate an expression to compute the maximum serialized size of an object.
fn max_size(attrs: &[Attribute], data: &Data) -> TokenStream {
    match *data {
        Data::Struct(ref data) => total_size(&data.fields),

        Data::Enum(ref data) => {
            let d_ty = enum_discriminant_type(attrs).unwrap();
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
            let d_ty = enum_discriminant_type(attrs).unwrap();
            let recurse = data.variants.iter().map(|v| {
                let ident = &v.ident;
                let d_val = enum_discriminant_value(&v.attrs);

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
                let recurse = fields.unnamed.iter().enumerate().map(|(_i, f)| {
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
                let d_val = enum_discriminant_value(&v.attrs);

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

            let d_ty = enum_discriminant_type(attrs).unwrap();
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
