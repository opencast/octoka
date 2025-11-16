# Load-testing utilities for Octoka

This app allows you to load test octoka, giving you information such as:
- How many requests (of a specific kind) per second can octoka handle?
- Do any requests start failing under too much load?

Currently, this is just a very bare bones, quickly written script!
We are using [`goose`](https://github.com/tag1consulting/goose) as the framework for writing load tests.

## Running

Be sure to build octoka in release mode, e.g. `cargo run -r`!
Also make sure that the configured log level is not "trace" or anything else that could print something per incoming request.
That would create a huge log and influences the result.

JWTs in the load tests are created using the keys in `util/keys`.
Be sure to serve the JWKS in that folder and configure the correct `trusted_keys`.


Run with:

```
cargo run -r -- --host http://localhost:4050 --report-file=report.html --no-reset-metrics --hatch-rate 5 --run-time 20s
```

There are many CLI options, i.e. run `cargo run -r -- -h` to see them all.
To get meaningful data, you likely have to adjust some of these values.

*Note*: there are multiple kinds of requests defined in `src/main.rs`.
By default a mix of all of them is executed.
To just run one of them, pass the `--scenarios` option, e.g. `--scenarios="foo"`.
List all scenarios via:

```
cargo run -r -- --scenarios-list
```
