// SOCMind 通用 JS
const API_BASE = '/api/v1';

// API 调用封装
async function apiGet(path, params = {}) {
    const query = new URLSearchParams(params).toString();
    const url = `${API_BASE}${path}${query ? '?' + query : ''}`;
    const resp = await fetch(url);
    return resp.json();
}

async function apiPost(path, data = {}) {
    const resp = await fetch(`${API_BASE}${path}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
    });
    return resp.json();
}

async function apiPatch(path, data = {}) {
    const resp = await fetch(`${API_BASE}${path}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
    });
    return resp.json();
}

async function apiPut(path, data = {}) {
    const resp = await fetch(`${API_BASE}${path}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
    });
    return resp.json();
}

async function apiUpload(path, formData) {
    const resp = await fetch(`${API_BASE}${path}`, {
        method: 'POST',
        body: formData,
    });
    return resp.json();
}

async function apiDelete(path, data = {}) {
    const resp = await fetch(`${API_BASE}${path}`, {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
    });
    return resp.json();
}

// 格式化时间
function fmtTime(ts) {
    if (!ts) return '-';
    const d = new Date(ts);
    return d.toLocaleString('zh-CN', { hour12: false });
}

function fmtDate(ts) {
    if (!ts) return '-';
    const d = new Date(ts);
    return d.toLocaleDateString('zh-CN');
}

// 风险等级样式
function severityBadge(severity) {
    const map = { critical: '严重', high: '高危', medium: '中危', low: '低危' };
    return `<span class="badge-severity badge-${severity}">${map[severity] || severity}</span>`;
}

function statusBadge(status) {
    const map = {
        new: '未处理', in_progress: '研判中', confirmed: '已确认',
        false_positive: '误报', closed: '已关闭',
        open: '开启', analyzing: '分析中',
        pending: '等待中', running: '运行中', success: '成功', failed: '失败',
    };
    return `<span class="badge-status badge-${status}">${map[status] || status}</span>`;
}

// Toast 通知
function showToast(message, type = 'success') {
    const toast = document.getElementById('toastContainer');
    if (!toast) return;
    const bg = { success: '#27ae60', error: '#e74c3c', warning: '#f39c12', info: '#3498db' };
    const el = document.createElement('div');
    el.style.cssText = `background:${bg[type] || '#333'};color:#fff;padding:12px 20px;border-radius:6px;margin-bottom:8px;font-size:14px;box-shadow:0 2px 8px rgba(0,0,0,0.15);animation:slideIn 0.3s ease;`;
    el.textContent = message;
    toast.appendChild(el);
    setTimeout(() => { el.style.opacity = '0'; el.style.transition = 'opacity 0.3s'; setTimeout(() => el.remove(), 300); }, 3000);
}

// 加载状态
function showLoading(container) {
    container.innerHTML = '<div class="loading"><div class="spinner"></div><p>加载中...</p></div>';
}

// 分页组件
function renderPagination(container, page, pageSize, total, onChange) {
    const totalPages = Math.ceil(total / pageSize) || 1;
    if (totalPages <= 1) { container.innerHTML = ''; return; }
    let html = '<nav><ul class="pagination pagination-sm mb-0">';
    html += `<li class="page-item ${page <= 1 ? 'disabled' : ''}"><a class="page-link" data-page="${page - 1}" href="javascript:void(0)">上一页</a></li>`;
    const start = Math.max(1, page - 2);
    const end = Math.min(totalPages, page + 2);
    for (let i = start; i <= end; i++) {
        html += `<li class="page-item ${i === page ? 'active' : ''}"><a class="page-link" data-page="${i}" href="javascript:void(0)">${i}</a></li>`;
    }
    html += `<li class="page-item ${page >= totalPages ? 'disabled' : ''}"><a class="page-link" data-page="${page + 1}" href="javascript:void(0)">下一页</a></li>`;
    html += `<li class="page-item disabled"><span class="page-link">共 ${total} 条</span></li>`;
    html += '</ul></nav>';
    container.innerHTML = html;
    container.querySelectorAll('.page-link[data-page]').forEach(el => {
        el.addEventListener('click', (e) => {
            e.preventDefault();
            const p = parseInt(el.dataset.page);
            if (p >= 1 && p <= totalPages) onChange(p);
        });
    });
}
