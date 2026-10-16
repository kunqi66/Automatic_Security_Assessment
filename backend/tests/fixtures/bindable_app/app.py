"""最小可绑定应用 —— 测试夹具，**不是靶场，不会被跑起来**。

它存在的唯一理由是让 `verify.routes.bind_route` 有一份真实源码可以反查。
`tests/verify_chain_fakes.py` 里的 `FakeTaintStep` 默认指向这里，
行号**由锚点字符串当场数出来**（`BINDABLE_SOURCE_LINE` / `BINDABLE_SINK_LINE`），
所以增删行不会让绑定静默失配 —— 只要下面那两句还在。

形状是刻意选的：`/search` + `request.args.get("q")` + **numeric 两列**的拼接 SQL，
`sqli` 的两条模板（union / boolean）在这个上下文里都成立。
"""

from flask import Flask, request

app = Flask(__name__)
DB = None


@app.route("/search")
def search():
    q = request.args.get("q", "1")
    cursor = DB.cursor()
    # ⚠️ 拼接是**故意的** —— 它是被反查的对象。本文件从不被 import、从不运行，
    # 只在测试里被 tree-sitter 解析，所以这条 S608 是夹具的本体而不是疏忽。
    cursor.execute("SELECT id, name FROM products WHERE id = " + q)  # noqa: S608
    return cursor.fetchall()
