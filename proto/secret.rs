// This file is generated by rust-protobuf 2.22.1. Do not edit
// @generated

// https://github.com/rust-lang/rust-clippy/issues/702
#![allow(unknown_lints)]
#![allow(clippy::all)]

#![allow(unused_attributes)]
#![cfg_attr(rustfmt, rustfmt::skip)]

#![allow(box_pointers)]
#![allow(dead_code)]
#![allow(missing_docs)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(trivial_casts)]
#![allow(unused_imports)]
#![allow(unused_results)]
//! Generated file from `proto/secret.proto`

/// Generated files are compatible only with the same version
/// of protobuf runtime.
// const _PROTOBUF_VERSION_CHECK: () = ::protobuf::VERSION_2_22_1;

#[derive(PartialEq,Clone,Default)]
pub struct AuthTokens {
    // message fields
    pub owner: ::std::string::String,
    pub meta: ::std::string::String,
    // special fields
    pub unknown_fields: ::protobuf::UnknownFields,
    pub cached_size: ::protobuf::CachedSize,
}

impl<'a> ::std::default::Default for &'a AuthTokens {
    fn default() -> &'a AuthTokens {
        <AuthTokens as ::protobuf::Message>::default_instance()
    }
}

impl AuthTokens {
    pub fn new() -> AuthTokens {
        ::std::default::Default::default()
    }

    // string owner = 1;


    pub fn get_owner(&self) -> &str {
        &self.owner
    }
    pub fn clear_owner(&mut self) {
        self.owner.clear();
    }

    // Param is passed by value, moved
    pub fn set_owner(&mut self, v: ::std::string::String) {
        self.owner = v;
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_owner(&mut self) -> &mut ::std::string::String {
        &mut self.owner
    }

    // Take field
    pub fn take_owner(&mut self) -> ::std::string::String {
        ::std::mem::replace(&mut self.owner, ::std::string::String::new())
    }

    // string meta = 2;


    pub fn get_meta(&self) -> &str {
        &self.meta
    }
    pub fn clear_meta(&mut self) {
        self.meta.clear();
    }

    // Param is passed by value, moved
    pub fn set_meta(&mut self, v: ::std::string::String) {
        self.meta = v;
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_meta(&mut self) -> &mut ::std::string::String {
        &mut self.meta
    }

    // Take field
    pub fn take_meta(&mut self) -> ::std::string::String {
        ::std::mem::replace(&mut self.meta, ::std::string::String::new())
    }
}

impl ::protobuf::Message for AuthTokens {
    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    ::protobuf::rt::read_singular_proto3_string_into(wire_type, is, &mut self.owner)?;
                },
                2 => {
                    ::protobuf::rt::read_singular_proto3_string_into(wire_type, is, &mut self.meta)?;
                },
                _ => {
                    ::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        if !self.owner.is_empty() {
            my_size += ::protobuf::rt::string_size(1, &self.owner);
        }
        if !self.meta.is_empty() {
            my_size += ::protobuf::rt::string_size(2, &self.meta);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::ProtobufResult<()> {
        if !self.owner.is_empty() {
            os.write_string(1, &self.owner)?;
        }
        if !self.meta.is_empty() {
            os.write_string(2, &self.meta)?;
        }
        os.write_unknown_fields(self.get_unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields(&self) -> &::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields(&mut self) -> &mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn as_any(&self) -> &dyn (::std::any::Any) {
        self as &dyn (::std::any::Any)
    }
    fn as_any_mut(&mut self) -> &mut dyn (::std::any::Any) {
        self as &mut dyn (::std::any::Any)
    }
    fn into_any(self: ::std::boxed::Box<Self>) -> ::std::boxed::Box<dyn (::std::any::Any)> {
        self
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        Self::descriptor_static()
    }

    fn new() -> AuthTokens {
        AuthTokens::new()
    }

    fn descriptor_static() -> &'static ::protobuf::reflect::MessageDescriptor {
        static descriptor: ::protobuf::rt::LazyV2<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::LazyV2::INIT;
        descriptor.get(|| {
            let mut fields = ::std::vec::Vec::new();
            fields.push(::protobuf::reflect::accessor::make_simple_field_accessor::<_, ::protobuf::types::ProtobufTypeString>(
                "owner",
                |m: &AuthTokens| { &m.owner },
                |m: &mut AuthTokens| { &mut m.owner },
            ));
            fields.push(::protobuf::reflect::accessor::make_simple_field_accessor::<_, ::protobuf::types::ProtobufTypeString>(
                "meta",
                |m: &AuthTokens| { &m.meta },
                |m: &mut AuthTokens| { &mut m.meta },
            ));
            ::protobuf::reflect::MessageDescriptor::new_pb_name::<AuthTokens>(
                "AuthTokens",
                fields,
                file_descriptor_proto()
            )
        })
    }

    fn default_instance() -> &'static AuthTokens {
        static instance: ::protobuf::rt::LazyV2<AuthTokens> = ::protobuf::rt::LazyV2::INIT;
        instance.get(AuthTokens::new)
    }
}

impl ::protobuf::Clear for AuthTokens {
    fn clear(&mut self) {
        self.owner.clear();
        self.meta.clear();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for AuthTokens {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for AuthTokens {
    fn as_ref(&self) -> ::protobuf::reflect::ReflectValueRef {
        ::protobuf::reflect::ReflectValueRef::Message(self)
    }
}

#[derive(PartialEq,Clone,Default)]
pub struct Auth {
    // message fields
    pub tokens: ::protobuf::SingularPtrField<AuthTokens>,
    // special fields
    pub unknown_fields: ::protobuf::UnknownFields,
    pub cached_size: ::protobuf::CachedSize,
}

impl<'a> ::std::default::Default for &'a Auth {
    fn default() -> &'a Auth {
        <Auth as ::protobuf::Message>::default_instance()
    }
}

impl Auth {
    pub fn new() -> Auth {
        ::std::default::Default::default()
    }

    // .secret.AuthTokens tokens = 1;


    pub fn get_tokens(&self) -> &AuthTokens {
        self.tokens.as_ref().unwrap_or_else(|| <AuthTokens as ::protobuf::Message>::default_instance())
    }
    pub fn clear_tokens(&mut self) {
        self.tokens.clear();
    }

    pub fn has_tokens(&self) -> bool {
        self.tokens.is_some()
    }

    // Param is passed by value, moved
    pub fn set_tokens(&mut self, v: AuthTokens) {
        self.tokens = ::protobuf::SingularPtrField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_tokens(&mut self) -> &mut AuthTokens {
        if self.tokens.is_none() {
            self.tokens.set_default();
        }
        self.tokens.as_mut().unwrap()
    }

    // Take field
    pub fn take_tokens(&mut self) -> AuthTokens {
        self.tokens.take().unwrap_or_else(|| AuthTokens::new())
    }
}

impl ::protobuf::Message for Auth {
    fn is_initialized(&self) -> bool {
        for v in &self.tokens {
            if !v.is_initialized() {
                return false;
            }
        };
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    ::protobuf::rt::read_singular_message_into(wire_type, is, &mut self.tokens)?;
                },
                _ => {
                    ::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        if let Some(ref v) = self.tokens.as_ref() {
            let len = v.compute_size();
            my_size += 1 + ::protobuf::rt::compute_raw_varint32_size(len) + len;
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::ProtobufResult<()> {
        if let Some(ref v) = self.tokens.as_ref() {
            os.write_tag(1, ::protobuf::wire_format::WireTypeLengthDelimited)?;
            os.write_raw_varint32(v.get_cached_size())?;
            v.write_to_with_cached_sizes(os)?;
        }
        os.write_unknown_fields(self.get_unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields(&self) -> &::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields(&mut self) -> &mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn as_any(&self) -> &dyn (::std::any::Any) {
        self as &dyn (::std::any::Any)
    }
    fn as_any_mut(&mut self) -> &mut dyn (::std::any::Any) {
        self as &mut dyn (::std::any::Any)
    }
    fn into_any(self: ::std::boxed::Box<Self>) -> ::std::boxed::Box<dyn (::std::any::Any)> {
        self
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        Self::descriptor_static()
    }

    fn new() -> Auth {
        Auth::new()
    }

    fn descriptor_static() -> &'static ::protobuf::reflect::MessageDescriptor {
        static descriptor: ::protobuf::rt::LazyV2<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::LazyV2::INIT;
        descriptor.get(|| {
            let mut fields = ::std::vec::Vec::new();
            fields.push(::protobuf::reflect::accessor::make_singular_ptr_field_accessor::<_, ::protobuf::types::ProtobufTypeMessage<AuthTokens>>(
                "tokens",
                |m: &Auth| { &m.tokens },
                |m: &mut Auth| { &mut m.tokens },
            ));
            ::protobuf::reflect::MessageDescriptor::new_pb_name::<Auth>(
                "Auth",
                fields,
                file_descriptor_proto()
            )
        })
    }

    fn default_instance() -> &'static Auth {
        static instance: ::protobuf::rt::LazyV2<Auth> = ::protobuf::rt::LazyV2::INIT;
        instance.get(Auth::new)
    }
}

impl ::protobuf::Clear for Auth {
    fn clear(&mut self) {
        self.tokens.clear();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for Auth {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for Auth {
    fn as_ref(&self) -> ::protobuf::reflect::ReflectValueRef {
        ::protobuf::reflect::ReflectValueRef::Message(self)
    }
}

#[derive(PartialEq,Clone,Default)]
pub struct Data {
    // message fields
    pub data: ::std::string::String,
    pub meta: ::std::string::String,
    // special fields
    pub unknown_fields: ::protobuf::UnknownFields,
    pub cached_size: ::protobuf::CachedSize,
}

impl<'a> ::std::default::Default for &'a Data {
    fn default() -> &'a Data {
        <Data as ::protobuf::Message>::default_instance()
    }
}

impl Data {
    pub fn new() -> Data {
        ::std::default::Default::default()
    }

    // string data = 1;


    pub fn get_data(&self) -> &str {
        &self.data
    }
    pub fn clear_data(&mut self) {
        self.data.clear();
    }

    // Param is passed by value, moved
    pub fn set_data(&mut self, v: ::std::string::String) {
        self.data = v;
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_data(&mut self) -> &mut ::std::string::String {
        &mut self.data
    }

    // Take field
    pub fn take_data(&mut self) -> ::std::string::String {
        ::std::mem::replace(&mut self.data, ::std::string::String::new())
    }

    // string meta = 2;


    pub fn get_meta(&self) -> &str {
        &self.meta
    }
    pub fn clear_meta(&mut self) {
        self.meta.clear();
    }

    // Param is passed by value, moved
    pub fn set_meta(&mut self, v: ::std::string::String) {
        self.meta = v;
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_meta(&mut self) -> &mut ::std::string::String {
        &mut self.meta
    }

    // Take field
    pub fn take_meta(&mut self) -> ::std::string::String {
        ::std::mem::replace(&mut self.meta, ::std::string::String::new())
    }
}

impl ::protobuf::Message for Data {
    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    ::protobuf::rt::read_singular_proto3_string_into(wire_type, is, &mut self.data)?;
                },
                2 => {
                    ::protobuf::rt::read_singular_proto3_string_into(wire_type, is, &mut self.meta)?;
                },
                _ => {
                    ::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        if !self.data.is_empty() {
            my_size += ::protobuf::rt::string_size(1, &self.data);
        }
        if !self.meta.is_empty() {
            my_size += ::protobuf::rt::string_size(2, &self.meta);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::ProtobufResult<()> {
        if !self.data.is_empty() {
            os.write_string(1, &self.data)?;
        }
        if !self.meta.is_empty() {
            os.write_string(2, &self.meta)?;
        }
        os.write_unknown_fields(self.get_unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields(&self) -> &::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields(&mut self) -> &mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn as_any(&self) -> &dyn (::std::any::Any) {
        self as &dyn (::std::any::Any)
    }
    fn as_any_mut(&mut self) -> &mut dyn (::std::any::Any) {
        self as &mut dyn (::std::any::Any)
    }
    fn into_any(self: ::std::boxed::Box<Self>) -> ::std::boxed::Box<dyn (::std::any::Any)> {
        self
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        Self::descriptor_static()
    }

    fn new() -> Data {
        Data::new()
    }

    fn descriptor_static() -> &'static ::protobuf::reflect::MessageDescriptor {
        static descriptor: ::protobuf::rt::LazyV2<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::LazyV2::INIT;
        descriptor.get(|| {
            let mut fields = ::std::vec::Vec::new();
            fields.push(::protobuf::reflect::accessor::make_simple_field_accessor::<_, ::protobuf::types::ProtobufTypeString>(
                "data",
                |m: &Data| { &m.data },
                |m: &mut Data| { &mut m.data },
            ));
            fields.push(::protobuf::reflect::accessor::make_simple_field_accessor::<_, ::protobuf::types::ProtobufTypeString>(
                "meta",
                |m: &Data| { &m.meta },
                |m: &mut Data| { &mut m.meta },
            ));
            ::protobuf::reflect::MessageDescriptor::new_pb_name::<Data>(
                "Data",
                fields,
                file_descriptor_proto()
            )
        })
    }

    fn default_instance() -> &'static Data {
        static instance: ::protobuf::rt::LazyV2<Data> = ::protobuf::rt::LazyV2::INIT;
        instance.get(Data::new)
    }
}

impl ::protobuf::Clear for Data {
    fn clear(&mut self) {
        self.data.clear();
        self.meta.clear();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for Data {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for Data {
    fn as_ref(&self) -> ::protobuf::reflect::ReflectValueRef {
        ::protobuf::reflect::ReflectValueRef::Message(self)
    }
}

#[derive(PartialEq,Clone,Default)]
pub struct Secret {
    // message fields
    pub auth: ::protobuf::SingularPtrField<Auth>,
    pub data: ::protobuf::SingularPtrField<Data>,
    // special fields
    pub unknown_fields: ::protobuf::UnknownFields,
    pub cached_size: ::protobuf::CachedSize,
}

impl<'a> ::std::default::Default for &'a Secret {
    fn default() -> &'a Secret {
        <Secret as ::protobuf::Message>::default_instance()
    }
}

impl Secret {
    pub fn new() -> Secret {
        ::std::default::Default::default()
    }

    // .secret.Auth auth = 1;


    pub fn get_auth(&self) -> &Auth {
        self.auth.as_ref().unwrap_or_else(|| <Auth as ::protobuf::Message>::default_instance())
    }
    pub fn clear_auth(&mut self) {
        self.auth.clear();
    }

    pub fn has_auth(&self) -> bool {
        self.auth.is_some()
    }

    // Param is passed by value, moved
    pub fn set_auth(&mut self, v: Auth) {
        self.auth = ::protobuf::SingularPtrField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_auth(&mut self) -> &mut Auth {
        if self.auth.is_none() {
            self.auth.set_default();
        }
        self.auth.as_mut().unwrap()
    }

    // Take field
    pub fn take_auth(&mut self) -> Auth {
        self.auth.take().unwrap_or_else(|| Auth::new())
    }

    // .secret.Data data = 2;


    pub fn get_data(&self) -> &Data {
        self.data.as_ref().unwrap_or_else(|| <Data as ::protobuf::Message>::default_instance())
    }
    pub fn clear_data(&mut self) {
        self.data.clear();
    }

    pub fn has_data(&self) -> bool {
        self.data.is_some()
    }

    // Param is passed by value, moved
    pub fn set_data(&mut self, v: Data) {
        self.data = ::protobuf::SingularPtrField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_data(&mut self) -> &mut Data {
        if self.data.is_none() {
            self.data.set_default();
        }
        self.data.as_mut().unwrap()
    }

    // Take field
    pub fn take_data(&mut self) -> Data {
        self.data.take().unwrap_or_else(|| Data::new())
    }
}

impl ::protobuf::Message for Secret {
    fn is_initialized(&self) -> bool {
        for v in &self.auth {
            if !v.is_initialized() {
                return false;
            }
        };
        for v in &self.data {
            if !v.is_initialized() {
                return false;
            }
        };
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    ::protobuf::rt::read_singular_message_into(wire_type, is, &mut self.auth)?;
                },
                2 => {
                    ::protobuf::rt::read_singular_message_into(wire_type, is, &mut self.data)?;
                },
                _ => {
                    ::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        if let Some(ref v) = self.auth.as_ref() {
            let len = v.compute_size();
            my_size += 1 + ::protobuf::rt::compute_raw_varint32_size(len) + len;
        }
        if let Some(ref v) = self.data.as_ref() {
            let len = v.compute_size();
            my_size += 1 + ::protobuf::rt::compute_raw_varint32_size(len) + len;
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::ProtobufResult<()> {
        if let Some(ref v) = self.auth.as_ref() {
            os.write_tag(1, ::protobuf::wire_format::WireTypeLengthDelimited)?;
            os.write_raw_varint32(v.get_cached_size())?;
            v.write_to_with_cached_sizes(os)?;
        }
        if let Some(ref v) = self.data.as_ref() {
            os.write_tag(2, ::protobuf::wire_format::WireTypeLengthDelimited)?;
            os.write_raw_varint32(v.get_cached_size())?;
            v.write_to_with_cached_sizes(os)?;
        }
        os.write_unknown_fields(self.get_unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields(&self) -> &::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields(&mut self) -> &mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn as_any(&self) -> &dyn (::std::any::Any) {
        self as &dyn (::std::any::Any)
    }
    fn as_any_mut(&mut self) -> &mut dyn (::std::any::Any) {
        self as &mut dyn (::std::any::Any)
    }
    fn into_any(self: ::std::boxed::Box<Self>) -> ::std::boxed::Box<dyn (::std::any::Any)> {
        self
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        Self::descriptor_static()
    }

    fn new() -> Secret {
        Secret::new()
    }

    fn descriptor_static() -> &'static ::protobuf::reflect::MessageDescriptor {
        static descriptor: ::protobuf::rt::LazyV2<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::LazyV2::INIT;
        descriptor.get(|| {
            let mut fields = ::std::vec::Vec::new();
            fields.push(::protobuf::reflect::accessor::make_singular_ptr_field_accessor::<_, ::protobuf::types::ProtobufTypeMessage<Auth>>(
                "auth",
                |m: &Secret| { &m.auth },
                |m: &mut Secret| { &mut m.auth },
            ));
            fields.push(::protobuf::reflect::accessor::make_singular_ptr_field_accessor::<_, ::protobuf::types::ProtobufTypeMessage<Data>>(
                "data",
                |m: &Secret| { &m.data },
                |m: &mut Secret| { &mut m.data },
            ));
            ::protobuf::reflect::MessageDescriptor::new_pb_name::<Secret>(
                "Secret",
                fields,
                file_descriptor_proto()
            )
        })
    }

    fn default_instance() -> &'static Secret {
        static instance: ::protobuf::rt::LazyV2<Secret> = ::protobuf::rt::LazyV2::INIT;
        instance.get(Secret::new)
    }
}

impl ::protobuf::Clear for Secret {
    fn clear(&mut self) {
        self.auth.clear();
        self.data.clear();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for Secret {
    fn as_ref(&self) -> ::protobuf::reflect::ReflectValueRef {
        ::protobuf::reflect::ReflectValueRef::Message(self)
    }
}

static file_descriptor_proto_data: &'static [u8] = b"\
    \n\x12proto/secret.proto\x12\x06secret\"6\n\nAuthTokens\x12\x14\n\x05own\
    er\x18\x01\x20\x01(\tR\x05owner\x12\x12\n\x04meta\x18\x02\x20\x01(\tR\
    \x04meta\"2\n\x04Auth\x12*\n\x06tokens\x18\x01\x20\x01(\x0b2\x12.secret.\
    AuthTokensR\x06tokens\".\n\x04Data\x12\x12\n\x04data\x18\x01\x20\x01(\tR\
    \x04data\x12\x12\n\x04meta\x18\x02\x20\x01(\tR\x04meta\"L\n\x06Secret\
    \x12\x20\n\x04auth\x18\x01\x20\x01(\x0b2\x0c.secret.AuthR\x04auth\x12\
    \x20\n\x04data\x18\x02\x20\x01(\x0b2\x0c.secret.DataR\x04dataB%\n\ncom.s\
    ecretB\x0bSecretProtoP\x01Z\x08secretpbb\x06proto3\
";

static file_descriptor_proto_lazy: ::protobuf::rt::LazyV2<::protobuf::descriptor::FileDescriptorProto> = ::protobuf::rt::LazyV2::INIT;

fn parse_descriptor_proto() -> ::protobuf::descriptor::FileDescriptorProto {
    ::protobuf::Message::parse_from_bytes(file_descriptor_proto_data).unwrap()
}

pub fn file_descriptor_proto() -> &'static ::protobuf::descriptor::FileDescriptorProto {
    file_descriptor_proto_lazy.get(|| {
        parse_descriptor_proto()
    })
}
