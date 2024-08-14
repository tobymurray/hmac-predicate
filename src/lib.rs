use bytes::Bytes;
use hex::FromHexError;
use hmac::{digest::InvalidLength, Hmac, Mac};
use http::{HeaderValue, Request};
use sha2::Sha256;
use thiserror::Error;
use tower::filter::Predicate;

#[derive(Debug, Clone)]
pub struct HmacQueryParamValidator {
	pub key: String,
}

/// The failure modes of HMAC verification, mostly for troubleshooting
#[derive(Error, Debug)]
pub enum HmacQueryParamError {
	#[error("Request did not have a query string")]
	NoQueryString,
	#[error("Request did not have an HMAC query param: {query_string}")]
	QueryStringButNoHmac { query_string: String },
	#[error("Hash key not appropriately set: {error:#?}")]
	HashKeyNotSet { error: InvalidLength },
	#[error("Failed decoding HMAC as hex string: {error:#?}")]
	HexDecodingError { error: FromHexError },
	#[error("Computed hash did not match provided hash")]
	HashVerificationFailed,
}

#[derive(Debug, Clone)]
pub struct HmacHeaderValidator {
	pub key: String,
	pub header_name: String,
}

/// The failure modes of HMAC verification, mostly for troubleshooting
#[derive(Error, Debug)]
pub enum HmacHeaderError {
	#[error("Request did not contain a '{header_name}' header.")]
	NoHeader { header_name: String },
	#[error("Request contained {num} headers with name '{header_name}'")]
	MultipleHeaders { num: usize, header_name: String },
	#[error("Hash key not appropriately set: {error:#?}")]
	HashKeyNotSet { error: InvalidLength },
	// #[error("Failed decoding HMAC as hex string: {error:#?}")]
	// HexDecodingError { error: FromHexError },
	// #[error("Computed hash did not match provided hash")]
	// HashVerificationFailed,
}

impl<T> Predicate<Request<T>> for HmacQueryParamValidator {
	type Request = http::Request<T>;
	fn check(&mut self, request: Request<T>) -> Result<Self::Request, tower::BoxError> {
		// 1. Get the entire query string in one shot
		let query = request.uri().query().ok_or(HmacQueryParamError::NoQueryString)?;

		// 2. Grab the hmac query parameter (both key and value), separate from the rest of the query params
		let (hmac, params): (Vec<_>, Vec<_>) =
			form_urlencoded::parse(query.as_bytes()).partition(|(key, _)| key == "hmac");
		let hmac = &hmac
			.first()
			.ok_or(HmacQueryParamError::QueryStringButNoHmac {
				query_string: query.to_string(),
			})?
			.1;

		// 3. Rebuild the query string without the hmac, as it's excluded from the hash
		let query_string_without_hmac = form_urlencoded::Serializer::new(String::new())
			.extend_pairs(params)
			.finish();

		// 4. Create a HMAC SHA256 hash function using key as the hash key
		let mut hasher = Hmac::<Sha256>::new_from_slice(self.key.as_bytes())
			.map_err(|e| HmacQueryParamError::HashKeyNotSet { error: e })?;

		// 5. Hash the remnants of the query string (with hmac removed)
		hasher.update(&query_string_without_hmac.into_bytes());

		// 6. The value in the query string is the result of the hash function represented as hexadecimal, represented
		// as a string. I say that slighly weirdly because you can't just compare the value to the computed hash, the
		// string needs to be decoded as hexadecimal (e.g. the characters '02' are the numerical value 2). At that
		// point the resultant "number" can be compared with the output of the hash function
		let hmac_bytes =
			hex::decode(hmac.as_bytes()).map_err(|e| HmacQueryParamError::HexDecodingError { error: e })?;

		// 7. Compare the Shopify-provided value to the freshly computed value
		hasher
			.verify(hmac_bytes.as_slice().into())
			.map_err(|_| HmacQueryParamError::HashVerificationFailed)?;

		Ok(request)
	}
}

impl<B: Into<Bytes>> Predicate<Request<B>> for HmacHeaderValidator
where
	for<'a> &'a [u8]: From<&'a B>,
{
	type Request = http::Request<B>;
	fn check(&mut self, request: Request<B>) -> Result<Self::Request, tower::BoxError> {
		// 1. Get any headers that match the provided name
		let header_values = request
			.headers()
			.get_all(&self.header_name)
			.into_iter()
			.collect::<Vec<&HeaderValue>>();

		// Return if there's not exactly 1
		if header_values.is_empty() {
			return Err(Box::new(HmacHeaderError::NoHeader {
				header_name: self.header_name.clone(),
			}));
		} else if header_values.len() > 1 {
			return Err(Box::new(HmacHeaderError::MultipleHeaders {
				num: header_values.len(),
				header_name: self.header_name.clone(),
			}));
		}

		// 2. Get the value of the header that matches the provided name
		let hmac = header_values.first().ok_or(HmacHeaderError::NoHeader {
			header_name: self.header_name.clone(),
		})?;

		// 3. Create a HMAC SHA256 hash function using key as the hash key
		let mut hasher = Hmac::<Sha256>::new_from_slice(self.key.as_bytes())
			.map_err(|e| HmacHeaderError::HashKeyNotSet { error: e })?;

		// 4. Hash the request body
		hasher.update(request.body().into());

		// 5. The value in the query string is the result of the hash function represented as hexadecimal, represented
		// as a string. I say that slighly weirdly because you can't just compare the value to the computed hash, the
		// string needs to be decoded as hexadecimal (e.g. the characters '02' are the numerical value 2). At that
		// point the resultant "number" can be compared with the output of the hash function
		let hmac_bytes =
			hex::decode(hmac.as_bytes()).map_err(|e| HmacQueryParamError::HexDecodingError { error: e })?;

		// 6. Compare the Shopify-provided value to the freshly computed value
		hasher
			.verify(hmac_bytes.as_slice().into())
			.map_err(|_| HmacQueryParamError::HashVerificationFailed)?;

		Ok(request)
	}
}
