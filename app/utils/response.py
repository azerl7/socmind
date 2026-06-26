"""统一响应格式工具"""


def success_response(data=None, message="success"):
    """成功响应"""
    return {"code": 0, "message": message, "data": data}


def error_response(code=40001, message="参数错误", data=None):
    """失败响应"""
    return {"code": code, "message": message, "data": data}


def paginated_response(items, page, page_size, total):
    """分页响应"""
    return success_response({
        "items": items,
        "page": page,
        "page_size": page_size,
        "total": total,
    })
