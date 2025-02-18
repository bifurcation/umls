use syn::*;

pub fn ty(attrs: &[Attribute]) -> Option<Type> {
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

pub fn value(attrs: &[Attribute]) -> Option<Expr> {
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
