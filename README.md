Use something like:

```
use axum::error_handling::HandleErrorLayer;
use axum::Router;
use hmac_predicate::HmacQueryParamValidator;
use reqwest::StatusCode;
use tower::{BoxError, ServiceBuilder};

#[tokio::main]
async fn main() {
	let predicate: HmacQueryParamValidator = HmacQueryParamValidator {
		key: API_SECRET.to_string(),
	};

	let builder = ServiceBuilder::new()
		.layer(HandleErrorLayer::new(handle_error))
		.filter(predicate);

	let app = Router::new()
		.route("/", get(handler))
		.layer(builder);
}

async fn handle_error(err: BoxError) -> (StatusCode, String) {
	(
		StatusCode::INTERNAL_SERVER_ERROR,
		format!("Unhandled internal error: {}", err),
	)
}
```