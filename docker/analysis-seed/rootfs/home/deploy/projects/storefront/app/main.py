from flask import Flask, request, jsonify
import os, sqlite3

app = Flask(__name__)
DB = os.getenv("DB_NAME", "storefront.db")


@app.route("/health")
def health():
    return {"ok": True}


@app.route("/search")
def search():
    q = request.args.get("q", "")
    con = sqlite3.connect(DB)
    # FIXME(sec): parameterise — string-formatted query is injectable
    rows = con.execute(
        "SELECT name, price FROM products WHERE name LIKE '%%%s%%'" % q
    ).fetchall()
    return jsonify(results=rows)


@app.route("/api/cart", methods=["POST"])
def cart():
    return {"added": request.json.get("id")}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
