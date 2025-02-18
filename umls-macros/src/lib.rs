mod deserialize;
mod enum_discriminant;
mod materialize;
mod serialize;
mod view;

#[proc_macro_derive(Serialize, attributes(discriminant))]
pub fn derive_serialize(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    serialize::derive(input)
}

#[proc_macro_derive(Deserialize, attributes(discriminant))]
pub fn derive_deserialize(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    deserialize::derive(input)
}

#[proc_macro_derive(View, attributes(discriminant))]
pub fn derive_view(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    view::derive(input)
}

// derive(Materialize) only works in limited circumstances.  If an object has a generic type
// parameter, then we can't compute its size in a way that is compatible with const generics.
// Generic lifetime parameters are fine.
#[proc_macro_derive(Materialize)]
pub fn derive_materialize(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    materialize::derive(input)
}
