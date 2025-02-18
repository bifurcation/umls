use proc_macro2::{Span, TokenStream};
use quote::{format_ident, quote, quote_spanned};
use syn::spanned::Spanned;
use syn::*;

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
    let as_view_body = as_view(&view_name, &input.attrs, &input.data);

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
    // impl<'a> BorrowDeserialize<'a> for FooView<'a, C> where C: Crypto {
    //     fn borrow_deserialize(reader: &mut impl BorrowRead<'a>) -> Result<Self> {
    //          Ok(Self {
    //              a: <ThingA::View<'a> as BorrowRead<'a>>::borrow_deserialize(),
    //              b: <ThingB::View<'a> as BorrowRead<'a>>::borrow_deserialize(),
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
        #view_type

        impl #view_impl_generics BorrowDeserialize #lifetime_generics for #view_name #view_ty_generics #view_where_clause {
            fn borrow_deserialize(reader: &mut impl BorrowRead #lifetime_generics) -> Result<Self> {
                todo!();
            }
        }

        impl #impl_generics View for #name #ty_generics #where_clause {
            type View<'a> = #view_name<'a>;

            fn as_view<'a>(&'a self) -> Self::View<'a> where Self: #lifetime {
                #as_view_body
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
                    #ident(<#ty as View>::View #lifetime_generics)
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

fn as_view(view_name: &Ident, _attrs: &[Attribute], data: &Data) -> TokenStream {
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
