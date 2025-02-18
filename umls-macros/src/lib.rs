use proc_macro2::{Span, TokenStream};
use quote::{format_ident, quote, quote_spanned};
use syn::spanned::Spanned;
use syn::*;

#[proc_macro_derive(Serialize, attributes(discriminant))]
pub fn derive_serialize(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
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

#[proc_macro_derive(View)]
pub fn derive_view(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
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
    let view_fields = view_fields(&input.attrs, &input.data);
    let as_view_body = as_view(&input.attrs, &input.data);

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
        pub struct #view_name #view_ty_generics #where_clause {
            #view_fields
        }

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

fn view_fields(_attrs: &[Attribute], data: &Data) -> TokenStream {
    match *data {
        Data::Struct(ref data) => match data.fields {
            Fields::Named(ref fields) => {
                let recurse = fields.named.iter().map(|f| {
                    let ident = &f.ident;
                    let ty = &f.ty;
                    quote_spanned! {f.span()=>
                        #ident: <#ty as View>::View<'a>,
                    }
                });
                quote! { #(#recurse)* }
            }
            _ => unimplemented!(),
        },

        _ => unimplemented!(),
        /*
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
        */
    }
}

fn as_view(_attrs: &[Attribute], data: &Data) -> TokenStream {
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
            _ => unimplemented!(),
        },

        _ => unimplemented!(),
        /*
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
        */
    }
}

// derive(Materialize) only works in limited circumstances.  If an object has a generic type
// parameter, then we can't compute its size in a way that is compatible with const generics.
// Generic lifetime parameters are fine.
#[proc_macro_derive(Materialize)]
pub fn derive_materialize(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
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
