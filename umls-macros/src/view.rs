use proc_macro2::{Span, TokenStream};
use quote::{format_ident, quote, quote_spanned};
use syn::spanned::Spanned;
use syn::*;

use crate::enum_discriminant;

pub fn derive(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let mut view_generics = input.generics.clone();
    let lifetime = Lifetime::new("'a", Span::call_site());
    let lifetime_param = GenericParam::Lifetime(LifetimeParam::new(lifetime.clone()));
    view_generics.params.insert(0, lifetime_param.clone());
    let lifetime_generics = quote! { < #lifetime_param > };

    let name = input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    let (view_impl_generics, view_ty_generics, view_where_clause) = view_generics.split_for_impl();

    let view_name = format_ident!("{}View", name);
    let view_type = view_type(
        &view_name,
        &view_ty_generics,
        &view_where_clause,
        &lifetime_generics,
        &input.attrs,
        &input.data,
    );
    let parse_body = parse(&lifetime_generics, &input.attrs, &input.data);
    let as_view_body = as_view(&view_name, &input.data);
    let from_view_body = from_view(&view_name, &input.data);

    // struct Foo<C> where C: Crypto {
    //     a: ThingA,
    //     b: ThingB,
    // }
    //
    // ==>
    //
    // struct FooView<'a, C> where C: Crypto {
    //     a: ThingA::View<'a>,
    //     b: ThingB::View<'a>,
    // }
    //
    // impl<'a> Parse<'a> for FooView<'a, C> where C: Crypto {
    //     fn parse(reader: &mut impl BorrowRead<'a>) -> Result<Self> {
    //          Ok(Self {
    //              a: <ThingA::View<'a> as BorrowRead<'a>>::parse(),
    //              b: <ThingB::View<'a> as BorrowRead<'a>>::parse(),
    //          })
    //     }
    // }
    //
    // impl<C> View for Foo<C> where C: Crypto {
    //     type View<'a> = FooView<'a, C>;
    //
    //     fn as_view<'a>(&'a self) -> Self::View<'a>
    //     where
    //         Self: 'a,
    //     {
    //         stack::update();
    //         FooView {
    //             self.a.as_view(),
    //             self.b.as_view(),
    //         }
    //     }
    // }

    let expanded = quote! {
        #[derive(Debug, PartialEq)]
        #view_type

        impl #view_impl_generics Parse #lifetime_generics for #view_name #view_ty_generics #view_where_clause {
            fn parse(reader: &mut impl BorrowRead #lifetime_generics) -> Result<Self> {
                #parse_body
            }
        }

        impl #impl_generics View for #name #ty_generics #where_clause {
            type View<'a> = #view_name #view_ty_generics;

            fn as_view<'a>(&'a self) -> Self::View<'a> where Self: #lifetime {
                #as_view_body
            }

            fn from_view<'a>(view: Self::View<'a>) -> Self {
                #from_view_body
            }
        }
    };

    proc_macro::TokenStream::from(expanded)
}

fn view_type(
    view_name: &Ident,
    view_ty_generics: &TypeGenerics,
    view_where_clause: &Option<&WhereClause>,
    lifetime_generics: &TokenStream,
    _attrs: &[Attribute],
    data: &Data,
) -> TokenStream {
    match *data {
        Data::Struct(ref data) => match data.fields {
            Fields::Named(ref fields) => {
                let recurse = fields.named.iter().map(|f| {
                    let ident = &f.ident;
                    let ty = &f.ty;
                    quote_spanned! {f.span()=>
                        #ident: <#ty as View>::View #lifetime_generics,
                    }
                });
                quote! {
                    pub struct #view_name #view_ty_generics #view_where_clause {
                        #(#recurse)*
                    }
                }
            }
            Fields::Unnamed(ref fields) => {
                let recurse = fields.unnamed.iter().map(|f| {
                    let ty = &f.ty;
                    quote_spanned! {f.span()=>
                        <#ty as View>::View  #lifetime_generics,
                    }
                });
                quote! {
                    pub struct #view_name #view_ty_generics (
                        #(#recurse)*
                    ) #view_where_clause;
                }
            }
            Fields::Unit => unimplemented!("Views for unit structs are not supported"),
        },

        Data::Enum(ref data) => {
            let recurse = data.variants.iter().map(|v| {
                let Fields::Unnamed(fields) = &v.fields else {
                    panic!("Invalid enum variant: Must be a tuple");
                };

                let Some(field) = fields.unnamed.iter().next() else {
                    panic!("Invalid enum variant: Must be a tuple with at least one element");
                };

                let ident = &v.ident;
                let ty = &field.ty;

                quote! {
                    #ident(<#ty as View>::View #lifetime_generics),
                }
            });

            quote! {
                pub enum #view_name #view_ty_generics #view_where_clause {
                    #(#recurse)*
                }
            }
        }

        // Unions are not supported
        Data::Union(_) => unimplemented!(),
    }
}

fn parse(lifetime_generics: &TokenStream, attrs: &[Attribute], data: &Data) -> TokenStream {
    match *data {
        Data::Struct(ref data) => match data.fields {
            Fields::Named(ref fields) => {
                let recurse = fields.named.iter().map(|f| {
                    let ty = &f.ty;
                    let ident = &f.ident;

                    let view = quote! { <#ty as View>::View #lifetime_generics };
                    quote_spanned! {f.span()=>
                        #ident: <#view as Parse>::parse(reader)?,
                    }
                });
                quote! { Ok(Self { #(#recurse)* }) }
            }
            Fields::Unnamed(ref fields) => {
                let recurse = fields.unnamed.iter().map(|f| {
                    let ty = &f.ty;
                    let view = quote! { <#ty as View>::View #lifetime_generics };
                    quote_spanned! {f.span()=>
                        <#view as Parse>::parse(reader)?,
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
                let view = quote! { <#ty as View>::View #lifetime_generics };

                quote! {
                    #d_val => {
                        let val = <#view as Parse>::parse(reader)?;
                        Ok(Self::#ident(val))
                    }
                }
            });

            let d_ty = enum_discriminant::ty(attrs).unwrap();
            quote! {
                let disc = <#d_ty as Parse>::parse(reader)?;
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

fn as_view(view_name: &Ident, data: &Data) -> TokenStream {
    match *data {
        Data::Struct(ref data) => match data.fields {
            Fields::Named(ref fields) => {
                let recurse = fields.named.iter().map(|f| {
                    let ident = &f.ident;
                    quote_spanned! {f.span()=>
                        #ident: self.#ident.as_view(),
                    }
                });
                quote! { Self::View{ #(#recurse)* } }
            }
            Fields::Unnamed(ref fields) => {
                let recurse = fields.unnamed.iter().enumerate().map(|(i, f)| {
                    let index = Index::from(i);
                    quote_spanned! {f.span()=>
                        self.#index.as_view(),
                    }
                });
                quote! { #view_name( #(#recurse)* ) }
            }
            Fields::Unit => unimplemented!("Views for unit structs are not supported"),
        },

        Data::Enum(ref data) => {
            let recurse = data.variants.iter().map(|v| {
                let ident = &v.ident;

                // XXX(RLB): Pretty sure this fails if the enum has a structure other than a
                // single, unnamed fields.  But I'm not sure we care about those cases.
                quote! {
                    Self::#ident(x) => #view_name::#ident(x.as_view()),
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

fn from_view(view_name: &Ident, data: &Data) -> TokenStream {
    match *data {
        Data::Struct(ref data) => match data.fields {
            Fields::Named(ref fields) => {
                let recurse = fields.named.iter().map(|f| {
                    let ident = &f.ident;
                    quote_spanned! {f.span()=>
                        #ident: View::from_view(view.#ident),
                    }
                });
                quote! { Self{ #(#recurse)* } }
            }
            Fields::Unnamed(ref fields) => {
                let recurse = fields.unnamed.iter().enumerate().map(|(i, f)| {
                    let index = Index::from(i);
                    quote_spanned! {f.span()=>
                        View::from_view(view.#index),
                    }
                });
                quote! { Self( #(#recurse)* ) }
            }
            Fields::Unit => unimplemented!("Views for unit structs are not supported"),
        },

        Data::Enum(ref data) => {
            let recurse = data.variants.iter().map(|v| {
                let ident = &v.ident;

                // XXX(RLB): Pretty sure this fails if the enum has a structure other than a
                // single, unnamed fields.  But I'm not sure we care about those cases.
                quote! {
                    #view_name::#ident(x) => Self::#ident(View::from_view(x)),
                }
            });

            quote! {
                match view {
                    #(#recurse)*
                }
            }
        }

        // Unions are not supported
        Data::Union(_) => unimplemented!(),
    }
}
