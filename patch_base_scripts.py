path = "templates/base.html"
with open(path, "r", encoding="utf-8") as f:
    content = f.read()

old = """    {% block content %}{% endblock %}
</div>
</body>"""

new = """    {% block content %}{% endblock %}
</div>
{% block scripts %}{% endblock %}
</body>"""

if old not in content:
    print("PATTERN NOT FOUND")
else:
    content = content.replace(old, new, 1)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    print("base.html patched")
