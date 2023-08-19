use hex::FromHexError;
use hmac::{
	digest::{InvalidLength, MacError},
	Hmac, Mac,
};
use http::Request;
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
	#[error("Computed hash did not match provided hash: {error:#?}")]
	HashVerificationFailed { error: MacError },
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
			.map_err(|e| HmacQueryParamError::HashVerificationFailed { error: e })?;

		Ok(request)
	}
}
