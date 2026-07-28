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
        "name": "Jenkins CI/CD",
        "category": "DevOps",
        "header_regex": [r"x-jenkins:.*", r"x-hud-version:.*"],
        "dom_regex": [r"jenkins-head-builder"],
        "favicon_mmh3": [],
        "endpoint_match": {"path": "/login", "status": 200, "contains": "Jenkins"}
    }
]
