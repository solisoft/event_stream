# Routes configuration

# Home page
get("/", "home#index", name: "root")
get("/health", "home#health")

# Documentation for the `es` event-streaming tool
get("/docs",         "docs#index",   name: "docs")
get("/docs/demo",    "docs#demo",    name: "docs_demo")
get("/docs/api",     "docs#api",     name: "docs_api")
get("/docs/cli",     "docs#cli",     name: "docs_cli")
get("/docs/storage", "docs#storage", name: "docs_storage")
get("/docs/cluster", "docs#cluster", name: "docs_cluster")
get("/docs/tools",   "docs#tools",   name: "docs_tools")

print("Routes loaded!")
