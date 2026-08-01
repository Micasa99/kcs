// ── Detail panel views ──────────────────────────────────────────────────────
import { api } from './state.js';
import { hwSection, open, highlightCard } from './topo.js';
import { containerActs } from './utils.js';

window.showServer = function () {
  window._view = { type: 'server' };
  window._lastNodeView = { type: 'server' };
  highlightCard();
  const { server, images, containers } = window.data;
  const searchId = 'search-' + Math.random().toFixed(3).slice(2);
  open(`
    <h3>server</h3>
    ${containers.length > 3 ? `<div class="search-wrap"><input class="search-box" id="${searchId}" placeholder="Filter containers..." oninput="filterItems(this)"></div>` : ''}
    <div class="node-name">${server.name}</div>
    <div class="node-ip">${server.ip}</div>
    <span class="pill ${server.status === 'Ready' ? 'ok' : 'err'}">${server.status}</span>
    ${window.data.nfs ? '<span class="pill info">NFS</span>' : '<span class="pill err">no NFS</span>'}
    ${server.taints && server.taints.length ? `<h4>taints</h4>${server.taints.map(t => `<div class="item"><span class="badge stopped"></span><span>${t}</span></div>`).join('')}` : ''}
    ${hwSection(server)}
    <h4>containers · ${containers.length}</h4>
    ${containers.length ? containers.map(c => `<div class="item" style="cursor:pointer" onclick="event.stopPropagation();showContainer('${c.name}')">
      <span class="badge ${c.status}"></span><span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;min-width:0">${c.name}</span>
      <span class="mono">${c.image.split('/').pop()}</span>
      ${(c.ports || []).length ? `<span class="mono" style="font-size:9px;margin-left:0">:${c.ports.map(p => typeof p === 'string' ? p.split('/')[0].split(':')[0] : p.port).join(',')}</span>` : ''}
      <span class="mono" style="font-size:9px">@${c.node || '?'}</span>
      <span class="item-acts">
        ${containerActs(c)}
        <button onclick="event.stopPropagation();doDelete('${c.name}')" class="danger" title="delete">✕</button>
      </span>
    </div>`).join('') : '<div class="empty">no containers</div>'}
    <h4>registry · ${images.length} images</h4>
    ${images.length ? images.map(i => `<div class="item">
      <span style="flex:1">${i}</span><span class="mono">:5000/${i}</span>
      <span class="item-acts">
        <button onclick="event.stopPropagation();showCreate('${i}')" title="run">▶</button>
        <button onclick="event.stopPropagation();doDeleteImage('${i}')" class="danger" title="forget">✕</button>
      </span>
    </div>`).join('') : '<div class="empty">no images built</div>'}`);
};

window.showWorker = function (i) {
  window._view = { type: 'worker', i };
  window._lastNodeView = { type: 'worker', i };
  highlightCard();
  const w = window._workers[i];
  const pods = window.data.containers.filter(c => c.node && c.node === w.ip);
  const searchId = 'search-' + Math.random().toFixed(3).slice(2);
  open(`
    <h3>worker</h3>
    ${pods.length > 3 ? `<div class="search-wrap"><input class="search-box" id="${searchId}" placeholder="Filter containers..." oninput="filterItems(this)"></div>` : ''}
    <div class="node-name">${w.name}</div>
    <div class="node-ip">${w.ip}</div>
    <span class="pill ${w.status === 'Ready' ? 'ok' : 'err'}">${w.status}</span>
    ${pods.length ? `<span class="pill ok">${pods.filter(p => p.status === 'running').length} running</span>` : ''}
    ${window.data.nfs ? '<span class="pill info">NFS</span>' : '<span class="pill err">no NFS</span>'}
    ${w.taints.length ? `<h4>taints</h4>${w.taints.map(t => `<div class="item"><span class="badge stopped"></span><span>${t}</span></div>`).join('')}` : ''}
    ${hwSection(w)}
    <h4>containers · ${pods.length}</h4>
    ${pods.length ? pods.map(c => `<div class="item" style="cursor:pointer" onclick="event.stopPropagation();showContainer('${c.name}')">
      <span class="badge ${c.status}"></span><span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;min-width:0">${c.name}</span>
      <span class="mono">${c.image.split('/').pop()}</span>
      ${(c.ports || []).length ? `<span class="mono" style="font-size:9px;margin-left:0">:${c.ports.map(p => typeof p === 'string' ? p.split('/')[0].split(':')[0] : p.port).join(',')}</span>` : ''}
      <span class="mono" style="font-size:9px">@${c.node || '?'}</span>
      <span class="item-acts">
        ${containerActs(c)}
        <button onclick="event.stopPropagation();doDelete('${c.name}')" class="danger" title="delete">✕</button>
      </span>
    </div>`).join('') : '<div class="empty">no containers on this node</div>'}`);
};

window.showContainer = async function (name) {
  window._view = { type: 'container', name };
  try {
    const c = await api('GET', `/containers/${name}`);
    const r = c.resources || {};
    const req = r.requests || {};
    const lim = r.limits || {};
    const hasHW = req['nvidia.com/gpu'] || req.cpu || req.memory;

    let hw = '';
    if (hasHW) {
      hw = '<h4>hardware</h4>';
      if (req.cpu) hw += `<div class="item"><span>CPU</span><span class="mono">${req.cpu}${lim.cpu && lim.cpu !== req.cpu ? ' / limit: ' + lim.cpu : ''}</span></div>`;
      if (req.memory) hw += `<div class="item"><span>Memory</span><span class="mono">${req.memory}${lim.memory && lim.memory !== req.memory ? ' / limit: ' + lim.memory : ''}</span></div>`;
      if (req['nvidia.com/gpu']) hw += `<div class="item"><span>GPU</span><span class="mono">${req['nvidia.com/gpu']}</span></div>`;
    }

    let vols = '';
    if (c.volumes && c.volumes.length) {
      vols = '<h4>volumes</h4>';
      vols += c.volumes.map(v => `<div class="item"><span>${v.mount_path}</span><span class="mono">${v.name}</span></div>`).join('');
    }

    let envs = '';
    if (c.env && Object.keys(c.env).length) {
      envs = '<h4>environment</h4>';
      envs += Object.entries(c.env).map(([k, v]) => `<div class="item"><span>${k}</span><span class="mono">${v}</span></div>`).join('');
    }

    let ports = '';
    if (c.ports && c.ports.length) {
      ports = '<h4>ports</h4>';
      ports += c.ports.map(p => {
        if (typeof p === 'string') {
          const [pp, proto = 'TCP'] = p.split('/');
          const [ext, int = ext] = pp.split(':');
          return `<div class="item"><span>${ext}→${int}</span><span class="mono">${proto}</span></div>`;
        }
        const addr = p.node_port && p.node_ip
          ? `${p.node_ip}:${p.node_port}`
          : (p.node_port ? `NodePort ${p.node_port}` : `ClusterIP ${p.cluster_ip}:${p.port}`);
        return `<div class="item" style="flex-direction:column;align-items:flex-start;gap:2px">
          <div style="display:flex;width:100%;justify-content:space-between">
            <span>${p.port}→${p.target_port}</span>
            <span class="mono">${p.protocol}</span>
          </div>
          <span class="mono" style="font-size:10px;color:var(--dim)">${addr}</span>
        </div>`;
      }).join('');
    }

    open(`
      <h3>container</h3>
      <div class="node-name">${c.name}</div>
      <div style="margin:4px 0 8px"><span class="pill ${c.status === 'running' ? 'ok' : c.status === 'terminating' ? 'info' : c.status === 'stopped' ? 'err' : 'info'}">${c.status}</span>${c.replicas > 1 ? `<span class="pill info">×${c.replicas}</span>` : ''}</div>
      <div class="item" style="flex-direction:column;align-items:flex-start;gap:2px">
        <span style="font-size:10px;color:var(--dim)">image</span>
        <span class="mono" style="font-size:11px">${c.image}</span>
      </div>
      ${hw}${ports}${vols}${envs}
      ${!hasHW && !c.volumes?.length && !Object.keys(c.env || {}).length && !c.ports?.length ? '<div class="empty">no hardware, volumes, ports, or env vars</div>' : ''}
      ${!c.ports?.length && (hasHW || c.volumes?.length || Object.keys(c.env || {}).length) ? '<div class="empty" style="padding:4px 0;font-size:10px">no exposed ports</div>' : ''}
      <h4>shell proxy · debug-only</h4>
      <div class="muted" style="margin-bottom:8px">V2 formal diagnostics use inspect/log.</div>
      ${(() => {
        const mine = window._proxies.filter(p => p.container === c.name);
        let h = '';
        if (mine.length) {
          h += mine.map(p => `<div class="item">
            <span style="flex:1">shell proxy${p.session ? ' · ' + p.session : ''}</span>
            <span class="item-acts">
              <button onclick="event.stopPropagation();copyProxy('${p.wrapper.replace(/'/g, "\\'")}')" title="copy CLAUDE_CODE_SHELL command" style="font-size:0;line-height:1"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg></button>
              <button onclick="event.stopPropagation();stopProxy('${p.container}','${p.session || ''}')" class="danger" title="stop proxy">✕</button>
            </span>
          </div>`).join('');
        } else {
          h += '<div class="empty">no proxy running</div>';
        }
        const pfId = c.name.replace(/[^a-zA-Z0-9]/g, '');
        const pfOpen = window._proxyFormOpen === c.name;
        h += `<button class="btn primary" style="margin-top:6px;display:${pfOpen ? 'none' : ''}" onclick="event.stopPropagation();toggleProxyForm('${c.name}')">Start Shell Proxy</button>
        <div id="pf-${pfId}" style="display:${pfOpen ? '' : 'none'};margin-top:4px">
          <input id="pfi-${pfId}" placeholder="session name (optional)" value="${pfOpen ? window._proxyFormSession.replace(/"/g, '&quot;') : ''}" oninput="window._proxyFormSession=this.value" style="width:100%;padding:4px 6px;border:1px solid var(--border);border-radius:5px;font:11px/1.4 -apple-system,BlinkMacSystemFont,'SF Pro Text','Segoe UI',sans-serif;background:var(--bg);color:var(--text);outline:none;margin-bottom:4px">
          <div style="display:flex;gap:4px">
            <button class="btn primary" style="flex:1;font-size:10px;padding:4px 0" onclick="event.stopPropagation();doStartProxy('${c.name}')">Start</button>
            <button style="flex:1;font-size:10px;padding:4px 0;background:var(--bg);border:1px solid var(--border);border-radius:6px;cursor:pointer" onclick="event.stopPropagation();hideProxyForm('${c.name}')">Cancel</button>
          </div>
        </div>`;
        return h;
      })()}
      <div style="margin-top:16px;display:flex;gap:6px">
        ${c.status === 'running' ? `<button class="btn primary" style="flex:1" onclick="doStop('${c.name}')">Stop</button>` : ''}
        ${c.status === 'stopped' ? `<button class="btn primary" style="flex:1" onclick="doStart('${c.name}')">Start</button>` : ''}
        ${c.status === 'terminating' ? `<span style="font-size:11px;color:var(--amber);flex:1;text-align:center;padding:7px 0">stopping…</span>` : ''}
        <button class="btn danger" style="flex:1" onclick="doDelete('${c.name}')">Delete</button>
      </div>
    `);
  } catch (e) {
    open(`<h3>container</h3><div class="empty">Failed to load: ${e.message}</div>`);
  }
};

window.showCreate = function (image) {
  window._view = { type: 'create' };
  const nodes = (window.data.workers || []).map(w => `<option value="${w.name}">${w.name}</option>`).join('');
  open(`
    <h3>new container</h3>
    <div class="fld"><label>Image</label><input id="f-image" value="${image || ''}" placeholder="nginx:alpine"></div>
    <div class="fld"><label>Name</label><input id="f-name" placeholder="auto"></div>
    <div class="fld-row">
      <div class="fld"><label>Ports</label><input id="f-ports" placeholder="8080"></div>
      <div class="fld"><label>Replicas</label><input id="f-replicas" value="1"></div>
    </div>
    <div class="fld"><label>Node</label><select id="f-node" style="width:100%;padding:6px 8px;border:1px solid var(--border);border-radius:5px;font:12px/1.4 -apple-system,BlinkMacSystemFont,'SF Pro Text','Segoe UI',sans-serif;background:var(--bg);color:var(--text);outline:none"><option value="">auto</option>${nodes}</select></div>
    <div class="fld"><label>Volumes</label><input id="f-volumes" placeholder="/data  or  /data, /srv/app:/mnt"></div>
    <div class="sep"></div>
    <h4>hardware (optional)</h4>
    <div class="fld-row">
      <div class="fld"><label>CPU</label><input id="f-cpu" placeholder="e.g. 500m, 1"></div>
      <div class="fld"><label>GPUs</label><input id="f-gpus" placeholder="0"></div>
    </div>
    <div class="fld"><label>Memory</label><input id="f-memory" placeholder="e.g. 256Mi, 1Gi"></div>
    <button class="btn primary" onclick="doCreate()">Create</button>
    <div id="f-msg" class="msg"></div>
  `);
};
