# `:live` and `:external` both need the network, so neither runs by default.
# Opt in with `mix test --only live` or `mix test --only external`.
ExUnit.start(exclude: [:live, :external])
