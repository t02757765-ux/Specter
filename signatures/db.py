from typing import List, Dict, Any

SIGNATURE_DATABASE: List[Dict[str, Any]] = [
    # --- CMS & CRM & ERP ---
    {
        "name": "WordPress",
        "category": "CMS",
        "header_regex": [r"x-powered-by:.*wordpress", r"link:.*<.*wp-json"],
        "dom_regex": [r"wp-content/themes", r"wp-includes/js"],
        "favicon_mmh3": ["116323821", "-123456789"],
        "endpoint_match": {"path": "/wp-json/", "status": 200, "contains": "namespaces"}
    },
    {
        "name": "Joomla",
        "category": "CMS",
        "header_regex": [r"x-content-encoded-by:.*joomla"],
        "dom_regex": [r"content=\"Joomla! - Open Source Content Management\"", r"/media/system/js/"],
        "favicon_mmh3": [],
        "endpoint_match": None
    },
    {
        "name": "Drupal",
        "category": "CMS",
        "header_regex": [r"x-generator:.*drupal", r"x-drupal-cache:.*"],
        "dom_regex": [r"Drupal\.settings", r"sites/all/modules"],
        "favicon_mmh3": [],
        "endpoint_match": None
    },
    {
        "name": "Magento",
        "category": "CMS",
        "header_regex": [r"set-cookie:.*frontend=.*"],
        "dom_regex": [r"Mage\.Cookies", r"skin/frontend/"],
        "favicon_mmh3": [],
        "endpoint_match": None
    },
    {
        "name": "Shopify",
        "category": "CMS",
        "header_regex": [r"x-shopify-stage:.*", r"server:.*shopify"],
        "dom_regex": [r"cdn\.shopify\.com"],
        "favicon_mmh3": [],
        "endpoint_match": None
    },
    {
        "name": "Odoo",
        "category": "ERP",
        "header_regex": [r"set-cookie:.*session_id.*", r"server:.*werkzeug"],
        "dom_regex": [r"odoo\.define", r"/web/static/src"],
        "favicon_mmh3": [],
        "endpoint_match": {"path": "/web/login", "status": 200, "contains": "Odoo"}
    },
    {
        "name": "SAP NetWeaver",
        "category": "ERP",
        "header_regex": [r"server:.*sap netweaver", r"sap-server:.*"],
        "dom_regex": [r"sap-iet-bc", r"sap-sys-id"],
        "favicon_mmh3": [],
        "endpoint_match": None
    },
    {
        "name": "SuiteCRM",
        "category": "CRM",
        "header_regex": [r"set-cookie:.*sugar_user_theme.*"],
        "dom_regex": [r"SuiteCRM", r"include/javascript/sugar_3\.js"],
        "favicon_mmh3": [],
        "endpoint_match": None
    },
    {
        "name": "SugarCRM",
        "category": "CRM",
        "header_regex": [r"set-cookie:.*PHPSESSID.*"],
        "dom_regex": [r"sidecar/minified/sidecar\.min\.js"],
        "favicon_mmh3": [],
        "endpoint_match": None
    },
    {
        "name": "Salesforce",
        "category": "CRM",
        "header_regex": [r"set-cookie:.*sfdc_lv.*", r"x-powered-by:.*salesforce"],
        "dom_regex": [r"force\.com", r"salesforce\.com"],
        "favicon_mmh3": [],
        "endpoint_match": None
    },

    # --- AI & MODERN TECH STACK ---
    {
        "name": "LangChain / LangServe",
        "category": "AI Framework",
        "header_regex": [r"x-langchain-service:.*"],
        "dom_regex": [r"LangChain", r"LangServe Playground"],
        "favicon_mmh3": [],
        "endpoint_match": {"path": "/docs", "status": 200, "contains": "LangChain"}
    },
    {
        "name": "Langflow",
        "category": "AI Framework",
        "header_regex": [],
        "dom_regex": [r"Langflow", r"langflow-chat"],
        "favicon_mmh3": [],
        "endpoint_match": {"path": "/api/v1/health", "status": 200, "contains": "status"}
    },
    {
        "name": "Flowise AI Orchestrator",
        "category": "AI Framework",
        "header_regex": [],
        "dom_regex": [r"flowise", r"canvas-wrapper"],
        "favicon_mmh3": [],
        "endpoint_match": {"path": "/api/v1/chatflows", "status": 200, "contains": "id"}
    },
    {
        "name": "Ollama AI Engine",
        "category": "AI Framework",
        "header_regex": [],
        "dom_regex": [r"Ollama is running"],
        "favicon_mmh3": [],
        "endpoint_match": {"path": "/api/tags", "status": 200, "contains": "models"}
    },
    {
        "name": "ChromaDB Vector Database",
        "category": "AI Framework",
        "header_regex": [],
        "dom_regex": [],
        "favicon_mmh3": [],
        "endpoint_match": {"path": "/api/v1/version", "status": 200, "contains": "1."}
    },
    {
        "name": "Pinecone Gateway",
        "category": "AI Framework",
        "header_regex": [r"server:.*pinecone"],
        "dom_regex": [],
        "favicon_mmh3": [],
        "endpoint_match": None
    },
    {
        "name": "Streamlit App Framework",
        "category": "AI Framework",
        "header_regex": [],
        "dom_regex": [r"streamlit\.config", r"streamlit-button"],
        "favicon_mmh3": ["-1223940192"],
        "endpoint_match": {"path": "/_stcore/health", "status": 200, "contains": "ok"}
    },
    {
        "name": "Gradio UI",
        "category": "AI Framework",
        "header_regex": [],
        "dom_regex": [r"gradio-app", r"window\.gradio_config"],
        "favicon_mmh3": [],
        "endpoint_match": {"path": "/config", "status": 200, "contains": "components"}
    },

    # --- WEB FRAMEWORKS & RUNTIMES ---
    {
        "name": "PHP Runtime",
        "category": "Web Runtime",
        "header_regex": [r"x-powered-by:.*php/([\d\.]+)"],
        "dom_regex": [],
        "favicon_mmh3": [],
        "endpoint_match": None
    },
    {
        "name": "Node.js Express",
        "category": "Web Framework",
        "header_regex": [r"x-powered-by:.*express"],
        "dom_regex": [],
        "favicon_mmh3": [],
        "endpoint_match": None
    },
    {
        "name": "Django Python Framework",
        "category": "Web Framework",
        "header_regex": [r"set-cookie:.*csrftoken.*"],
        "dom_regex": [r"csrfmiddlewaretoken"],
        "favicon_mmh3": [],
        "endpoint_match": None
    },
    {
        "name": "Flask Python Framework",
        "category": "Web Framework",
        "header_regex": [r"server:.*werkzeug"],
        "dom_regex": [],
        "favicon_mmh3": [],
        "endpoint_match": None
    },
    {
        "name": "FastAPI Framework",
        "category": "Web Framework",
        "header_regex": [r"server:.*uvicorn"],
        "dom_regex": [],
        "favicon_mmh3": [],
        "endpoint_match": {"path": "/docs", "status": 200, "contains": "Swagger UI"}
    },
    {
        "name": "Ruby on Rails",
        "category": "Web Framework",
        "header_regex": [r"x-powered-by:.*phusion passenger", r"set-cookie:.*_session_id.*"],
        "dom_regex": [r"csrf-param.*authenticity_token"],
        "favicon_mmh3": [],
        "endpoint_match": None
    },
    {
        "name": "ASP.NET Core",
        "category": "Web Framework",
        "header_regex": [r"x-powered-by:.*asp\.net", r"server:.*kestrel"],
        "dom_regex": [],
        "favicon_mmh3": [],
        "endpoint_match": None
    },
    {
        "name": "Laravel PHP Framework",
        "category": "Web Framework",
        "header_regex": [r"set-cookie:.*laravel_session.*"],
        "dom_regex": [],
        "favicon_mmh3": [],
        "endpoint_match": None
    },
    {
        "name": "Spring Boot",
        "category": "Web Framework",
        "header_regex": [r"x-application-context:.*"],
        "dom_regex": [r"Whitelabel Error Page"],
        "favicon_mmh3": [],
        "endpoint_match": {"path": "/actuator/health", "status": 200, "contains": "UP"}
    },

    # --- INFRASTRUCTURE & DEVOPS ---
    {
        "name": "Kubernetes Dashboard",
        "category": "DevOps",
        "header_regex": [],
        "dom_regex": [r"kubernetes-dashboard", r"ng-app=\"kubernetesDashboard\""],
        "favicon_mmh3": [],
        "endpoint_match": {"path": "/api/v1/login/status", "status": 200, "contains": "token"}
    },
    {
        "name": "Docker Registry",
        "category": "DevOps",
        "header_regex": [r"docker-distribution-api-version:.*registry/2\.0"],
        "dom_regex": [],
        "favicon_mmh3": [],
        "endpoint_match": {"path": "/v2/", "status": 200, "contains": "{}"}
    },
    {
        "name": "Jenkins CI/CD",
        "category": "DevOps",
        "header_regex": [r"x-jenkins:.*", r"x-hud-version:.*"],
        "dom_regex": [r"jenkins-head-builder"],
        "favicon_mmh3": [],
        "endpoint_match": {"path": "/login", "status": 200, "contains": "Jenkins"}
    },
    {
        "name": "Grafana Dashboard",
        "category": "Infrastructure",
        "header_regex": [r"set-cookie:.*grafana_session.*"],
        "dom_regex": [r"window\.grafanaBootData"],
        "favicon_mmh3": [],
        "endpoint_match": {"path": "/api/health", "status": 200, "contains": "database"}
    },
    {
        "name": "Prometheus Server",
        "category": "Infrastructure",
        "header_regex": [],
        "dom_regex": [r"Prometheus Time Series Collection"],
        "favicon_mmh3": [],
        "endpoint_match": {"path": "/-/healthy", "status": 200, "contains": "Prometheus"}
    },
    {
        "name": "RabbitMQ Management",
        "category": "Infrastructure",
        "header_regex": [r"server:.*cowboy"],
        "dom_regex": [r"<title>RabbitMQ Management</title>"],
        "favicon_mmh3": [],
        "endpoint_match": {"path": "/api/overview", "status": 200, "contains": "rabbitmq_version"}
    },
    {
        "name": "Apache Kafka REST Proxy",
        "category": "Infrastructure",
        "header_regex": [],
        "dom_regex": [],
        "favicon_mmh3": [],
        "endpoint_match": {"path": "/topics", "status": 200, "contains": "["}
    }
]
