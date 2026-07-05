# Documentation site for the `es` event-streaming tool.

class DocsController < Controller
    static {
        this.layout = "docs"
    }

    # GET /docs
    def index
        @section = "overview"
        @title = "es — basic event streaming in Rust"
        render("docs/index", { "layout": "docs" })
    end

    # GET /docs/demo
    def demo
        @section = "demo"
        @title = "Quickstart demo — es"
        render("docs/demo", { "layout": "docs" })
    end

    # GET /docs/api
    def api
        @section = "api"
        @title = "HTTP API — es"
        render("docs/api", { "layout": "docs" })
    end

    # GET /docs/cli
    def cli
        @section = "cli"
        @title = "CLI reference — es"
        render("docs/cli", { "layout": "docs" })
    end

    # GET /docs/storage
    def storage
        @section = "storage"
        @title = "Storage format — es"
        render("docs/storage", { "layout": "docs" })
    end

    # GET /docs/cluster
    def cluster
        @section = "cluster"
        @title = "Cluster setup — es"
        render("docs/cluster", { "layout": "docs" })
    end

    # GET /docs/tools
    def tools
        @section = "tools"
        @title = "Backup & restore — es"
        render("docs/tools", { "layout": "docs" })
    end
end
