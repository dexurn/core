dev: export RUSTFLAGS = --cfg debug_assertions
dev:
	wasm-pack build --dev --target web --out-dir dist/pkg

prod:
	wasm-pack build --release --target web --out-dir dist/pkg

clean:
	rm -rf dist/pkg

.PHONY: dev prod clean
