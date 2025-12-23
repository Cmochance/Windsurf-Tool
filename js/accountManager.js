// accountManager.js - 账号管理模块
// 负责账号列表的加载、显示、添加、删除、导出等操作

const AccountManager = {
  /**
   * 加载并显示账号列表
   */
  async loadAccounts() {
    console.log('开始加载账号列表...');
    const result = await window.ipcRenderer.invoke('get-accounts');
    console.log('IPC 返回结果:', result);
    const accounts = result.success ? (result.accounts || []) : [];
    console.log('账号数量:', accounts.length);
    const listEl = document.getElementById('accountsList');
    
    if (!listEl) {
      console.error('找不到 accountsList 元素');
      return;
    }
    
    // 过滤掉无效账号（空对象或没有邮箱的）
    const validAccounts = accounts.filter(acc => acc && acc.email);
    
    console.log('开始渲染', validAccounts.length, '个账号');
    
    // 按账号类型分组（忽略大小写）
    const typeGroups = {
      'Pro': [],
      'Enterprise': [],
      'Teams': [],
      'Trial': [],
      'Free': [],
      'Other': []
    };
    
    validAccounts.forEach(acc => {
      const type = (acc.type || '').toLowerCase().trim();
      if (!type || type === '-') {
        // 没有类型或未定义的归类到"其他"
        typeGroups['Other'].push(acc);
      } else if (type.includes('pro')) {
        typeGroups['Pro'].push(acc);
      } else if (type.includes('enterprise')) {
        typeGroups['Enterprise'].push(acc);
      } else if (type.includes('team')) {
        typeGroups['Teams'].push(acc);
      } else if (type.includes('trial')) {
        typeGroups['Trial'].push(acc);
      } else if (type.includes('free')) {
        typeGroups['Free'].push(acc);
      } else {
        // 未知类型也归类到"其他"
        typeGroups['Other'].push(acc);
      }
    });
    
    // 统计信息
    let totalCount = validAccounts.length;
    let activeCount = 0;
    let warningCount = 0;
    let expiredCount = 0;
    
    // 判断 Token 状态
    function getTokenStatus(account) {
      if (!account || !account.apiKey) {
        return {
          text: '未获取 Token',
          color: '#999999',
          valid: false
        };
      }
      
      if (!account.refreshToken) {
        return {
          text: 'Token 不完整',
          color: '#ff9500',
          valid: false
        };
      }
      
      return {
        text: 'Token 正常',
        color: '#34c759',
        valid: true
      };
    }
    
    // 构造表头
    let html = `
      <div class="account-item header">
        <div class="acc-col acc-col-index">ID</div>
        <div class="acc-col acc-col-email">邮箱</div>
        <div class="acc-col acc-col-password">密码</div>
        <div class="acc-col acc-col-type">类型</div>
        <div class="acc-col acc-col-credits">积分</div>
        <div class="acc-col acc-col-used">已用</div>
        <div class="acc-col acc-col-usage">使用率</div>
        <div class="acc-col acc-col-expiry">到期时间</div>
        <div class="acc-col acc-col-status">Token</div>
        <div class="acc-col acc-col-note">备注</div>
        <div class="acc-col acc-col-actions">操作</div>
      </div>
    `;
    
    // 如果没有账号，显示空提示
    if (validAccounts.length === 0) {
      html += `<div class="account-item" style="grid-column: 1 / -1; text-align:center; color:#999; padding:40px;">暂无账号</div>`;
    }
    
    // 分组颜色配置
    const groupConfig = {
      'Pro': { color: '#007aff', label: 'Pro' },
      'Enterprise': { color: '#5856d6', label: 'Enterprise' },
      'Teams': { color: '#ff9500', label: 'Teams' },
      'Trial': { color: '#34c759', label: 'Trial' },
      'Free': { color: '#8e8e93', label: 'Free' },
      'Other': { color: '#999', label: '其他' }
    };
    
    // 渲染单个账号行的函数
    const renderAccountRow = (acc, index) => {
      const expiry = this.calculateExpiry(acc.createdAt, acc.expiresAt);
      const tokenStatus = getTokenStatus(acc);

      // 统计分类（只有有 expiresAt 时才统计到期状态）
      if (acc.expiresAt) {
        if (expiry.isExpired) {
          expiredCount++;
        } else if (expiry.daysLeft <= 3) {
          warningCount++;
          activeCount++;
        } else {
          activeCount++;
        }
      } else {
        activeCount++;
      }

      const expiryText = acc.expiresAt && expiry.expiryDate
        ? expiry.expiryDate.toLocaleDateString('zh-CN', { year: 'numeric', month: '2-digit', day: '2-digit' })
        : '-';

      const tokenStatusText = tokenStatus.text;
      const tokenStatusColor = tokenStatus.color;
      const safePassword = acc.password || '';
      const accountType = acc.type || '-';
      const accountCredits = acc.credits !== undefined ? acc.credits : '-';
      const accountUsedCredits = acc.usedCredits !== undefined ? acc.usedCredits : '-';
      const accountUsage = acc.usage !== undefined ? acc.usage + '%' : '-';
      const maskedPassword = '••••••';

      return `
        <div class="account-item" data-id="${acc.id}" data-email="${acc.email}" data-password="${safePassword}">
          <div class="acc-col acc-col-index">${index}</div>
          <div class="acc-col acc-col-email" onclick="AccountManager.copyEmailText(event)" title="点击复制: ${acc.email}">${acc.email || ''}</div>
          <div class="acc-col acc-col-password" data-password="${safePassword}">
            <span class="password-display password-masked">${maskedPassword}</span>
            <span class="password-display password-text" style="display:none;" onclick="AccountManager.copyPasswordText(event)" title="点击复制密码">${safePassword}</span>
            <button class="password-toggle" onclick="AccountManager.togglePassword(event)" title="显示/隐藏密码">
              <i data-lucide="eye" style="width: 12px; height: 12px;"></i>
            </button>
          </div>
          <div class="acc-col acc-col-type">${accountType || '-'}</div>
          <div class="acc-col acc-col-credits">${accountCredits}</div>
          <div class="acc-col acc-col-used">${accountUsedCredits}</div>
          <div class="acc-col acc-col-usage">${accountUsage}</div>
          <div class="acc-col acc-col-expiry">${expiryText}</div>
          <div class="acc-col acc-col-status" style="color:${tokenStatusColor};">${tokenStatusText}</div>
          <div class="acc-col acc-col-note" onclick="AccountManager.editNote('${acc.id}', event)" title="点击编辑备注">
            <span class="note-text">${acc.note || '-'}</span>
          </div>
          <div class="acc-col acc-col-actions">
            <button class="acc-btn-icon" data-tooltip="更多操作" onclick="AccountManager.showMoreMenu(event, ${JSON.stringify(acc).replace(/"/g, '&quot;').replace(/'/g, "&apos;")})">
              <i data-lucide="more-horizontal" style="width: 16px; height: 16px; color: #6e6e73;"></i>
            </button>
          </div>
        </div>
      `;
    };
    
    // 按分组顺序渲染账号
    let globalIndex = 1;
    const groupOrder = ['Pro', 'Enterprise', 'Teams', 'Trial', 'Free', 'Other'];
    
    groupOrder.forEach(groupName => {
      const accounts = typeGroups[groupName];
      if (accounts.length > 0) {
        const config = groupConfig[groupName];
        // 添加分组标题
        html += `
          <div class="account-group-header" style="grid-column: 1 / -1; display: flex; align-items: center; gap: 6px; padding: 6px 12px; background: linear-gradient(to right, ${config.color}15, transparent); border-left: 3px solid ${config.color}; margin: 0 0 0 0; font-size: 13px; font-weight: 500; color: ${config.color};">
            <span>${config.label}</span>
            <span style="font-weight: 400; color: #8e8e93; font-size: 12px;">(${accounts.length})</span>
          </div>
        `;
        // 渲染该分组的账号
        accounts.forEach(acc => {
          html += renderAccountRow(acc, globalIndex++);
        });
      }
    });

    listEl.innerHTML = html;
    
    // 初始化Lucide图标（延迟执行确保DOM完全渲染）
    if (typeof lucide !== 'undefined') {
      // 使用 requestAnimationFrame 确保在下一帧渲染
      requestAnimationFrame(() => {
        lucide.createIcons();
        console.log('图标初始化完成');
      });
    }
    
    // 绑定右键菜单
    const accountRows = listEl.querySelectorAll('.account-item:not(.header)');
    accountRows.forEach(row => {
      row.addEventListener('contextmenu', (e) => {
        e.preventDefault();
        // 使用 data-email 属性获取原始邮箱,避免复制后文本变化的问题
        const email = row.getAttribute('data-email');
        const account = validAccounts.find(acc => acc.email === email);
        if (account) {
          this.showAccountContextMenu(e, account);
        }
      });
    });
    
    // 更新统计信息 - 显示顶部信息行
    const topInfoRow = document.getElementById('topInfoRow');
    if (topInfoRow) topInfoRow.style.display = 'flex';
    const totalEl = document.getElementById('totalCount');
    const activeEl = document.getElementById('activeCount');
    const warningEl = document.getElementById('warningCount');
    const expiredEl = document.getElementById('expiredCount');
    if (totalEl) totalEl.textContent = totalCount;
    if (activeEl) activeEl.textContent = activeCount;
    if (warningEl) warningEl.textContent = warningCount;
    if (expiredEl) expiredEl.textContent = expiredCount;
  },

  /**
   * 计算账号到期时间
   * 优先使用 API 返回的 expiresAt，否则根据创建时间计算（13天）
   */
  calculateExpiry(createdAt, expiresAt) {
    let expiry;
    
    // 优先使用 API 返回的到期时间
    if (expiresAt) {
      expiry = new Date(expiresAt);
    } else if (createdAt) {
      // 如果没有 expiresAt，根据创建时间计算（13天）
      const created = new Date(createdAt);
      expiry = new Date(created);
      expiry.setDate(expiry.getDate() + 13);
    } else {
      // 没有任何时间信息
      return {
        expiryDate: null,
        daysLeft: 0,
        isExpired: true,
        expiryText: '已到期',
        expiryColor: '#e74c3c'
      };
    }
    
    const now = new Date();
    const diffTime = expiry - now;
    const daysLeft = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
    const isExpired = daysLeft <= 0;
    
    return {
      expiryDate: expiry,
      daysLeft,
      isExpired,
      expiryText: isExpired ? '已到期' : `剩余${daysLeft}天`,
      expiryColor: isExpired ? '#e74c3c' : (daysLeft <= 3 ? '#ff9500' : '#007aff')
    };
  },

  /**
   * 显示添加账号表单
   */
  showAddAccountForm() {
    const modal = document.getElementById('addAccountModal');
    if (modal) {
      modal.classList.add('active');
      // 聚焦到邮箱输入框
      setTimeout(() => {
        const emailInput = document.getElementById('manualEmail');
        if (emailInput) emailInput.focus();
      }, 100);
    }
  },

  /**
   * 隐藏添加账号表单
   */
  hideAddAccountForm() {
    const modal = document.getElementById('addAccountModal');
    if (modal) modal.classList.remove('active');
    
    // 清空输入框（安全检查）
    const emailInput = document.getElementById('manualEmail');
    const passwordInput = document.getElementById('manualPassword');
    if (emailInput) emailInput.value = '';
    if (passwordInput) passwordInput.value = '';
    const apiKeyInput = document.getElementById('manualApiKey');
    if (apiKeyInput) apiKeyInput.value = '';
  },

  /**
   * 手动添加账号
   */
  async addManualAccount() {
    const email = document.getElementById('manualEmail').value;
    const password = document.getElementById('manualPassword').value;
    const apiKeyInput = document.getElementById('manualApiKey');
    const apiKey = apiKeyInput ? apiKeyInput.value.trim() : '';
    
    if (!email || !password) {
      showCustomAlert('请输入邮箱和密码', 'warning');
      return;
    }
    
    // 构建账号对象
    const accountData = {
      email,
      password
    };
    
    // 如果有 API Key，添加到账号数据中
    if (apiKey) {
      accountData.apiKey = apiKey;
    }
    
    const result = await window.ipcRenderer.invoke('add-account', accountData);
    
    if (result.success) {
      this.hideAddAccountForm();
      this.loadAccounts();
      // 使用自定义居中提示
      if (typeof showCenterMessage === 'function') {
        showCenterMessage('账号添加成功', 'success');
      }
    } else {
      if (typeof showCenterMessage === 'function') {
        showCenterMessage('添加失败: ' + result.error, 'error', 5000);
      } else {
        showCustomAlert('添加失败: ' + result.error, 'error');
      }
    }
  },

  /**
   * 删除账号
   */
  async deleteAccount(event) {
    event.stopPropagation();
    
    const btn = event.target.closest('button');
    if (!btn) {
      console.error('找不到删除按钮');
      return;
    }
    
    const id = btn.getAttribute('data-id');
    const email = btn.getAttribute('data-email');
    
    if (!id) {
      console.error('账号ID不存在');
      showCustomAlert('无法删除：账号ID不存在', 'error');
      return;
    }
    
    // 二次确认（使用自定义弹窗）
    const confirmed = await showCustomConfirm({
      title: '删除账号',
      message: `确定要删除账号 ${email || '未知'} 吗？`,
      subMessage: '此操作无法撤销！',
      confirmText: '删除',
      type: 'danger'
    });
    
    if (!confirmed) {
      return;
    }
    
    try {
      const result = await window.ipcRenderer.invoke('delete-account', id);
      
      if (result.success) {
        // 刷新列表
        await this.loadAccounts();
        
        // 显示成功提示
        if (typeof showToast === 'function') {
          showToast('删除成功！', 'success');
        } else {
          showCustomAlert('删除成功！', 'success');
        }
      } else {
        throw new Error(result.error || '删除失败');
      }
    } catch (error) {
      console.error('删除账号失败:', error);
      showCustomAlert('删除失败：' + error.message, 'error');
    }
  },

  /**
   * 删除全部账号
   */
  async deleteAllAccounts() {
    try {
      // 获取账号列表
      const result = await window.ipcRenderer.invoke('get-accounts');
      
      if (!result.success) {
        throw new Error(result.error || '获取账号列表失败');
      }
      
      if (!result.accounts || result.accounts.length === 0) {
        showCustomAlert('当前没有账号可删除', 'info');
        return;
      }
      
      const accountCount = result.accounts.length;
      
      // 第一次确认
      const firstConfirm = await showCustomConfirm({
        title: '删除全部账号',
        message: `警告：此操作将删除全部 ${accountCount} 个账号！`,
        subMessage: '删除后无法恢复，确定要继续吗？',
        confirmText: '继续',
        type: 'danger'
      });
      if (!firstConfirm) return;
      
      // 第二次确认（最后确认）
      const finalConfirm = await showCustomConfirm({
        title: '最后确认',
        message: `真的要删除全部 ${accountCount} 个账号吗？`,
        subMessage: '请再次确认！此操作不可撤销！',
        confirmText: '确定删除',
        type: 'danger'
      });
      if (!finalConfirm) return;
      
      // 执行删除
      const deleteResult = await window.ipcRenderer.invoke('delete-all-accounts');
      
      if (deleteResult.success) {
        // 刷新列表
        await this.loadAccounts();
        
        // 显示成功提示
        if (typeof showToast === 'function') {
          showToast(`成功删除了 ${accountCount} 个账号`, 'success');
        } else {
          showCustomAlert(`成功删除了 ${accountCount} 个账号`, 'success');
        }
      } else {
        throw new Error(deleteResult.error || '删除失败');
      }
    } catch (error) {
      console.error('删除全部账号失败:', error);
      showCustomAlert('删除失败：' + error.message, 'error');
    }
  },

  /**
   * 导出账号 - 支持分类导出
   * @param {string} type - 导出类型: 'all'(全部), 'pro'(Pro账号), 'free'(Free账号), 'enterprise', 'teams', 'trial'
   */
  async exportAccounts(type = 'all') {
    try {
      const result = await window.ipcRenderer.invoke('get-accounts');
      
      if (!result.success || !result.accounts || result.accounts.length === 0) {
        showCustomAlert('没有账号可导出', 'info');
        return;
      }
      
      let accounts = result.accounts;
      let exportTypeName = '全部';
      
      // 根据类型筛选账号
      if (type === 'pro') {
        accounts = accounts.filter(acc => acc.type && acc.type.toLowerCase() === 'pro');
        exportTypeName = 'Pro';
        if (accounts.length === 0) {
          showCustomAlert('没有Pro账号可导出', 'info');
          return;
        }
      } else if (type === 'free') {
        accounts = accounts.filter(acc => !acc.type || acc.type.toLowerCase() === 'free' || acc.type === '-');
        exportTypeName = 'Free';
        if (accounts.length === 0) {
          showCustomAlert('没有Free账号可导出', 'info');
          return;
        }
      } else if (type === 'enterprise') {
        accounts = accounts.filter(acc => acc.type && acc.type.toLowerCase() === 'enterprise');
        exportTypeName = 'Enterprise';
        if (accounts.length === 0) {
          showCustomAlert('没有Enterprise账号可导出', 'info');
          return;
        }
      } else if (type === 'teams') {
        accounts = accounts.filter(acc => acc.type && acc.type.toLowerCase() === 'teams');
        exportTypeName = 'Teams';
        if (accounts.length === 0) {
          showCustomAlert('没有Teams账号可导出', 'info');
          return;
        }
      } else if (type === 'trial') {
        accounts = accounts.filter(acc => acc.type && acc.type.toLowerCase() === 'trial');
        exportTypeName = 'Trial';
        if (accounts.length === 0) {
          showCustomAlert('没有Trial账号可导出', 'info');
          return;
        }
      }
      
      // 构建导出数据（JSON 格式）
      const exportData = {
        exportTime: new Date().toISOString(),
        exportTimeLocal: new Date().toLocaleString('zh-CN'),
        totalCount: accounts.length,
        accounts: accounts.map(acc => ({
          id: acc.id,
          email: acc.email,
          password: acc.password,
          firstName: acc.firstName,
          lastName: acc.lastName,
          name: acc.name,
          apiKey: acc.apiKey,
          apiServerUrl: acc.apiServerUrl,
          refreshToken: acc.refreshToken,
          createdAt: acc.createdAt,
          type: acc.type,
          credits: acc.credits,
          usage: acc.usage
        }))
      };
      
      // 转换为格式化的 JSON 字符串
      const jsonContent = JSON.stringify(exportData, null, 2);
      
      // 根据类型生成文件名
      const typePrefix = type || 'all';
      const defaultFileName = `windsurf-accounts-${typePrefix}-${Date.now()}.json`;
      
      const saveResult = await window.ipcRenderer.invoke('save-file-dialog', {
        title: `导出${exportTypeName}账号`,
        defaultPath: defaultFileName,
        filters: [
          { name: 'JSON 文件', extensions: ['json'] },
          { name: '所有文件', extensions: ['*'] }
        ],
        content: jsonContent
      });
      
      if (saveResult.success) {
        if (typeof showToast === 'function') {
          showToast(`成功导出 ${accounts.length} 个${exportTypeName}账号`, 'success');
        } else {
          showCustomAlert(`账号已成功导出到:\n${saveResult.filePath}\n\n共导出 ${accounts.length} 个${exportTypeName}账号`, 'success');
        }
      } else if (saveResult.cancelled) {
        // 用户取消了保存
      } else {
        throw new Error(saveResult.error || '保存失败');
      }
    } catch (error) {
      console.error('导出账号失败:', error);
      showCustomAlert('导出失败: ' + error.message, 'error');
    }
  },

  /**
   * 导出单个账号 - 导出为 JSON 格式
   */
  async exportSingleAccount(event) {
    const btn = event.target.closest('button');
    const accountData = btn.getAttribute('data-account');
    
    try {
      const account = JSON.parse(accountData);
      
      // 构建导出数据（JSON 格式，包含该账号的所有信息）
      const exportData = {
        exportTime: new Date().toISOString(),
        exportTimeLocal: new Date().toLocaleString('zh-CN'),
        account: {
          id: account.id,
          email: account.email,
          password: account.password,
          firstName: account.firstName,
          lastName: account.lastName,
          name: account.name,
          apiKey: account.apiKey,
          apiServerUrl: account.apiServerUrl,
          refreshToken: account.refreshToken,
          createdAt: account.createdAt,
          type: account.type,
          credits: account.credits,
          usage: account.usage
        }
      };
      
      // 转换为格式化的 JSON 字符串
      const jsonContent = JSON.stringify(exportData, null, 2);
      
      const saveResult = await window.ipcRenderer.invoke('save-file-dialog', {
        title: '导出账号',
        defaultPath: `windsurf-account-${account.email.replace('@', '_')}-${Date.now()}.json`,
        filters: [
          { name: 'JSON 文件', extensions: ['json'] },
          { name: '所有文件', extensions: ['*'] }
        ],
        content: jsonContent
      });
      
      if (saveResult.success) {
        if (typeof showToast === 'function') {
          showToast('账号已导出', 'success');
        } else {
          showCustomAlert(`账号已成功导出到:\n${saveResult.filePath}`, 'success');
        }
      } else if (saveResult.cancelled) {
        // 用户取消了保存
      } else {
        throw new Error(saveResult.error || '保存失败');
      }
    } catch (error) {
      console.error('导出账号失败:', error);
      showCustomAlert('导出失败: ' + error.message, 'error');
    }
  },

  /**
   * 切换账号 - 直接实现，带实时日志弹窗
   */
  async switchAccount(event) {
    const btn = event.target.closest('button');
    const accountId = btn.getAttribute('data-id');
    
    try {
      // 获取所有账号
      const accountsResult = await window.ipcRenderer.invoke('get-accounts');
      if (!accountsResult.success || !accountsResult.accounts) {
        showCustomAlert('获取账号列表失败', 'error');
        return;
      }
      
      const account = accountsResult.accounts.find(acc => acc.id === accountId);
      if (!account) {
        showCustomAlert('账号不存在', 'error');
        return;
      }
      
      // 显示切换确认
      const confirmed = await showCustomConfirm({
        title: '切换账号',
        message: `确定要切换到账号：${account.email} 吗？`,
        subMessage: '这将关闭当前的 Windsurf 应用并重新启动',
        confirmText: '切换',
        type: 'info'
      });
      if (!confirmed) return;
      
      // 创建日志显示模态框
      const modal = document.createElement('div');
      modal.className = 'modal-overlay active';
      modal.style.zIndex = '10000';
      modal.innerHTML = `
        <div class="modal-dialog modern-modal" style="max-width: 550px;" onclick="event.stopPropagation()">
          <div class="modern-modal-header">
            <div class="modal-title-row">
              <i data-lucide="refresh-cw" style="width: 24px; height: 24px; color: #007aff;"></i>
              <h3 class="modal-title">切换账号</h3>
            </div>
            <button class="modal-close-btn" id="closeSwitchModal" title="关闭">
              <i data-lucide="x" style="width: 20px; height: 20px;"></i>
            </button>
          </div>
          
          <div class="modern-modal-body">
            <div style="background: #f5f5f7; padding: 12px; border-radius: 8px; margin-bottom: 16px;">
              <div style="font-size: 13px; color: #86868b; margin-bottom: 4px;">目标账号</div>
              <div style="font-size: 15px; font-weight: 600; color: #1d1d1f;">${account.email}</div>
            </div>
            
            <div style="background: #1d1d1f; border-radius: 8px; padding: 12px; height: 240px; overflow-y: auto; font-family: 'Monaco', 'Menlo', monospace; font-size: 11px; line-height: 1.5;" id="switchLogContainer">
              <div style="color: #34c759;">准备切换账号...</div>
            </div>
          </div>
          
          <div class="modern-modal-footer" id="switchFooter">
            <div style="flex: 1; text-align: left; color: #86868b; font-size: 13px;" id="switchStatus">
              正在处理...
            </div>
          </div>
        </div>
      `;
      
      document.body.appendChild(modal);
      
      // 初始化图标
      if (typeof lucide !== 'undefined') {
        lucide.createIcons();
      }
      
      const logContainer = document.getElementById('switchLogContainer');
      const statusEl = document.getElementById('switchStatus');
      const closeBtn = document.getElementById('closeSwitchModal');
      
      // 切号状态标记
      let isSwitching = true;
      let switchAborted = false;
      
      // 关闭按钮处理
      closeBtn.onclick = async () => {
        if (isSwitching && !switchAborted) {
          const confirmAbort = await showCustomConfirm({
            title: '中断切号',
            message: '切号正在进行中，强制关闭可能导致数据不完整',
            subMessage: '确定要强制关闭吗？',
            confirmText: '强制关闭',
            type: 'warning'
          });
          
          if (!confirmAbort) {
            return;
          }
          
          switchAborted = true;
          addLog('用户中断切号操作');
          statusEl.textContent = '已中断';
          statusEl.style.color = '#ff9500';
        }
        
        // 清理资源
        if (logListener) {
          window.ipcRenderer.removeListener('switch-log', logListener);
        }
        modal.remove();
      };
      
      // 添加日志函数
      function addLog(message) {
        let color = '#ffffff';
        if (message.includes('') || message.includes('成功')) {
          color = '#34c759';
        } else if (message.includes('') || message.includes('失败') || message.includes('错误')) {
          color = '#ff3b30';
        } else if (message.includes('') || message.includes('警告')) {
          color = '#ff9500';
        } else if (message.includes('==========')) {
          color = '#007aff';
        }
        
        const log = document.createElement('div');
        log.style.color = color;
        log.textContent = message;
        logContainer.appendChild(log);
        logContainer.scrollTop = logContainer.scrollHeight;
        
        // 更新状态
        if (message.includes('切换完成')) {
          isSwitching = false;
          statusEl.textContent = '切换成功';
          statusEl.style.color = '#34c759';
        } else if (message.includes('切换失败')) {
          isSwitching = false;
          statusEl.textContent = '切换失败';
          statusEl.style.color = '#ff3b30';
        }
      }
      
      // 监听实时日志
      const logListener = (event, log) => {
        addLog(log);
      };
      window.ipcRenderer.on('switch-log', logListener);
      
      // 执行切换
      addLog('开始执行账号切换...');
      const result = await window.ipcRenderer.invoke('switch-account', account);
      
      if (result.success) {
        addLog('账号切换完成');
        // 切换成功，延迟刷新页面
        setTimeout(() => {
          window.location.reload();
        }, 2000);
      } else {
        addLog(`切换失败: ${result.error}`);
        statusEl.textContent = '切换失败';
        statusEl.style.color = '#ff3b30';
      }
      
      // 清理监听器
      isSwitching = false;
      window.ipcRenderer.removeListener('switch-log', logListener);
      
      // 点击背景关闭
      modal.onclick = (e) => {
        if (e.target === modal && !isSwitching) {
          modal.remove();
        }
      };
      
    } catch (error) {
      console.error('切换账号失败:', error);
      showCustomAlert(`切换失败: ${error.message}`, 'error');
    }
  },

  /**
   * 查看账号详情 - 使用模态框展示
   */
  viewAccountDetails(event) {
    const btn = event.target.closest('button');
    const accountData = btn.getAttribute('data-account');
    
    try {
      const account = JSON.parse(accountData);
      
      // 创建模态框
      const modal = document.createElement('div');
      modal.className = 'modal-overlay active';
      modal.style.zIndex = '10000';
      
      const expiry = this.calculateExpiry(account.createdAt, account.expiresAt);
      
      // 格式化到期时间显示（只有有 expiresAt 时才显示）
      let expiryDisplay = '-';
      if (account.expiresAt && expiry.expiryDate) {
        const dateStr = expiry.expiryDate.toLocaleDateString('zh-CN', { year: 'numeric', month: 'long', day: 'numeric' });
        if (expiry.isExpired) {
          expiryDisplay = `${dateStr} (已过期)`;
        } else {
          expiryDisplay = `${dateStr} (剩余${expiry.daysLeft}天)`;
        }
      }
      
      modal.innerHTML = `
        <div class="modal-dialog modern-modal" style="max-width: 380px;" onclick="event.stopPropagation()">
          <div class="modern-modal-header" style="padding: 14px 16px;">
            <div class="modal-title-row">
              <i data-lucide="user" style="width: 16px; height: 16px; color: #007aff;"></i>
              <h3 style="margin: 0; font-size: 14px; font-weight: 600;">账号详情</h3>
            </div>
            <button class="modal-close-btn" onclick="this.closest('.modal-overlay').remove()" style="width: 24px; height: 24px;">
              <i data-lucide="x" style="width: 14px; height: 14px;"></i>
            </button>
          </div>
          
          <div class="modern-modal-body" style="padding: 16px; max-height: 60vh; overflow-y: auto;">
            <!-- 基本信息 -->
            <div style="display: grid; gap: 6px; font-size: 12px; margin-bottom: 12px;">
              <div style="display: flex; justify-content: space-between;">
                <span style="color: #86868b;">邮箱</span>
                <span style="font-weight: 500; max-width: 200px; overflow: hidden; text-overflow: ellipsis;">${account.email || '-'}</span>
              </div>
              <div style="display: flex; justify-content: space-between;">
                <span style="color: #86868b;">密码</span>
                <span style="font-weight: 500;">${account.password || '-'}</span>
              </div>
              <div style="display: flex; justify-content: space-between;">
                <span style="color: #86868b;">类型</span>
                <span style="font-weight: 500; color: #007aff;">${account.type || '-'}</span>
              </div>
              <div style="display: flex; justify-content: space-between;">
                <span style="color: #86868b;">积分</span>
                <span style="font-weight: 500;">${account.credits !== undefined ? account.credits : '-'}</span>
              </div>
              <div style="display: flex; justify-content: space-between;">
                <span style="color: #86868b;">到期</span>
                <span style="font-weight: 500; color: ${expiry.expiryColor};">${expiryDisplay}</span>
              </div>
            </div>
            
            ${account.apiKey ? `
            <!-- API Key -->
            <div style="margin-bottom: 10px;">
              <div style="font-size: 11px; color: #86868b; margin-bottom: 4px; display: flex; justify-content: space-between; align-items: center;">
                <span>API Key</span>
                <button onclick="AccountManager.copyToClipboard('${account.apiKey}').then(() => { if(typeof showToast === 'function') showToast('已复制', 'success'); })" 
                  style="background: none; border: none; color: #007aff; cursor: pointer; font-size: 11px; padding: 0;">复制</button>
              </div>
              <div style="background: #18181b; padding: 8px; border-radius: 4px; font-family: monospace; font-size: 9px; color: #a1a1aa; word-break: break-all; max-height: 40px; overflow-y: auto;">
                ${account.apiKey}
              </div>
            </div>
            ` : ''}
            
            ${account.refreshToken ? `
            <!-- Refresh Token -->
            <div style="margin-bottom: 10px;">
              <div style="font-size: 11px; color: #86868b; margin-bottom: 4px; display: flex; justify-content: space-between; align-items: center;">
                <span>Refresh Token</span>
                <button onclick="AccountManager.copyToClipboard('${account.refreshToken}').then(() => { if(typeof showToast === 'function') showToast('已复制', 'success'); })" 
                  style="background: none; border: none; color: #007aff; cursor: pointer; font-size: 11px; padding: 0;">复制</button>
              </div>
              <div style="background: #18181b; padding: 8px; border-radius: 4px; font-family: monospace; font-size: 9px; color: #a1a1aa; word-break: break-all; max-height: 40px; overflow-y: auto;">
                ${account.refreshToken}
              </div>
            </div>
            ` : ''}
          </div>
          
          <div class="modern-modal-footer" style="padding: 12px 16px;">
            <button class="btn btn-secondary" onclick="this.closest('.modal-overlay').remove()" style="font-size: 12px; padding: 6px 16px;">
              关闭
            </button>
          </div>
        </div>
      `;
      
      // 点击背景关闭
      modal.onclick = (e) => {
        if (e.target === modal) {
          modal.remove();
        }
      };
      
      document.body.appendChild(modal);
      
      // 初始化图标
      if (typeof lucide !== 'undefined') {
        lucide.createIcons();
      }
    } catch (error) {
      console.error('查看账号详情失败:', error);
      showCustomAlert('查看详情失败: ' + error.message, 'error');
    }
  },

  /**
   * 刷新账号信息 - 查询积分并更新到 JSON 文件
   */
  async refreshAccountInfo(event) {
    const btn = event.target.closest('button');
    const accountData = btn.getAttribute('data-account');
    
    try {
      const account = JSON.parse(accountData);
      
      // 检查 AccountQuery 模块是否已加载
      if (typeof window.AccountQuery === 'undefined') {
        console.error('AccountQuery 模块未加载');
        showCustomAlert('查询模块未加载，请刷新页面重试', 'error');
        return;
      }
      
      if (!account.refreshToken) {
        showCustomAlert('该账号缺少 refreshToken，无法刷新', 'warning');
        return;
      }
      
      if (typeof showToast === 'function') {
        showToast('正在刷新账号信息...', 'info');
      }
      
      // 使用 accountQuery.js 中的 queryAccount 方法
      // queryAccount 已经内置了自动Token刷新和重新登录逻辑
      const queryResult = await window.AccountQuery.queryAccount(account);
      
      if (queryResult.success) {
        // 准备更新的账号数据
        const updatedAccount = {
          id: account.id,
          type: queryResult.planName || account.type || '-',
          credits: queryResult.totalCredits || 0, // 总积分
          usage: queryResult.usagePercentage || 0, // 使用率
          totalCredits: queryResult.totalCredits || 0,
          usedCredits: queryResult.usedCredits || 0,
          expiresAt: queryResult.expiresAt || null // 保存到期时间
        };
        
        // 如果查询结果包含新的 Token 信息,也一起更新
        if (queryResult.newTokenData) {
          updatedAccount.idToken = queryResult.newTokenData.idToken;
          updatedAccount.idTokenExpiresAt = queryResult.newTokenData.idTokenExpiresAt;
          updatedAccount.refreshToken = queryResult.newTokenData.refreshToken;
        }
        
        // 调用 IPC 更新账号信息到 JSON 文件
        const updateResult = await window.ipcRenderer.invoke('update-account', updatedAccount);
        
        if (updateResult.success) {
          // 刷新列表显示
          await this.loadAccounts();
          
          if (typeof showToast === 'function') {
            showToast(`刷新成功！类型: ${updatedAccount.type}, 总积分: ${updatedAccount.credits}`, 'success');
          } else {
            showCustomAlert(`刷新成功！\n类型: ${updatedAccount.type}\n总积分: ${updatedAccount.credits}\n使用率: ${updatedAccount.usage}%`, 'success');
          }
        } else {
          throw new Error(updateResult.error || '更新账号信息失败');
        }
      } else {
        console.error('刷新失败，详细信息:', queryResult);
        const errorMsg = queryResult.error || '未知错误';
        
        // 提供更友好的错误提示
        let userMessage = `刷新失败：${errorMsg}`;
        let detailHints = [];
        
        if (errorMsg.includes('账号缺少邮箱或密码')) {
          detailHints.push('该账号缺少登录凭据，请手动重新获取Token');
        } else if (errorMsg.includes('401')) {
          detailHints.push('Token验证失败，请检查控制台日志查看详细错误信息');
        } else if (errorMsg.includes('重新获取Token失败')) {
          detailHints.push('邮箱或密码错误，请检查登录凭据是否正确');
        }
        
        this.showErrorModal(userMessage, detailHints);
      }
    } catch (error) {
      console.error('刷新账号信息失败:', error);
      console.error('错误堆栈:', error.stack);
      
      let errorMsg = `刷新失败: ${error.message}`;
      let detailHints = [];
      if (error.message.includes('401') || error.message.includes('Token')) {
        detailHints.push('请打开控制台（F12）查看详细错误日志');
      }
      
      this.showErrorModal(errorMsg, detailHints);
    }
  },

  /**
   * 切换密码显示/隐藏
   */
  togglePassword(event) {
    // 阻止事件冒泡
    event.stopPropagation();
    
    // 获取按钮元素
    const btn = event.target.closest('button.password-toggle');
    if (!btn) {
      console.error('找不到密码切换按钮');
      return;
    }
    
    // 获取密码列
    const passwordCol = btn.closest('.acc-col-password');
    if (!passwordCol) {
      console.error('找不到密码列元素');
      return;
    }
    
    const masked = passwordCol.querySelector('.password-masked');
    const text = passwordCol.querySelector('.password-text');
    const icon = btn.querySelector('i');
    
    if (!masked || !text) {
      console.error('找不到密码显示元素');
      return;
    }
    
    // 切换显示状态
    if (masked.style.display !== 'none') {
      masked.style.display = 'none';
      text.style.display = 'inline';
      if (icon) icon.setAttribute('data-lucide', 'eye-off');
    } else {
      masked.style.display = 'inline';
      text.style.display = 'none';
      if (icon) icon.setAttribute('data-lucide', 'eye');
    }
    
    // 重新初始化图标（只初始化当前按钮的图标）
    if (typeof lucide !== 'undefined' && icon) {
      requestAnimationFrame(() => {
        lucide.createIcons({ icons: { eye: lucide.icons.Eye, 'eye-off': lucide.icons.EyeOff }, nameAttr: 'data-lucide' });
      });
    }
  },

  /**
   * 复制邮箱
   */
  async copyEmailText(event) {
    event.stopPropagation();
    
    const emailEl = event.target.closest('.acc-col-email');
    if (!emailEl) {
      console.error('找不到邮箱元素');
      return;
    }
    
    // 先保存原始文本和颜色
    const originalText = emailEl.textContent.trim();
    const originalColor = emailEl.style.color;
    
    try {
      await this.copyToClipboard(originalText);
      
      emailEl.textContent = '已复制';
      emailEl.style.color = '#34c759';
      
      setTimeout(() => {
        emailEl.textContent = originalText;
        emailEl.style.color = originalColor;
      }, 1000);
    } catch (error) {
      console.error('复制邮箱失败:', error);
      showCustomAlert('复制失败: ' + error.message, 'error');
    }
  },

  /**
   * 复制密码
   */
  async copyPasswordText(event) {
    event.stopPropagation();
    
    const passwordEl = event.target.closest('.password-text');
    if (!passwordEl) {
      console.error('找不到密码文本元素');
      return;
    }
    
    const password = passwordEl.textContent.trim();
    
    try {
      await this.copyToClipboard(password);
      
      const originalText = passwordEl.textContent;
      const originalColor = passwordEl.style.color;
      
      passwordEl.textContent = '已复制';
      passwordEl.style.color = '#34c759';
      
      setTimeout(() => {
        passwordEl.textContent = originalText;
        passwordEl.style.color = originalColor;
      }, 1000);
    } catch (error) {
      console.error('复制密码失败:', error);
      showCustomAlert('复制失败: ' + error.message, 'error');
    }
  },

  /**
   * 复制到剪贴板
   */
  async copyToClipboard(text) {
    try {
      const result = await window.ipcRenderer.invoke('copy-to-clipboard', text);
      if (!result.success) {
        throw new Error(result.error || '复制失败');
      }
    } catch (error) {
      console.error('复制失败:', error);
      throw error;
    }
  },

  /**
   * 显示导入账号表单 - 调用 renderer.js 中的实现
   * 注意：导入账号的完整实现在 renderer.js 中
   */
  showImportAccountForm() {
    // 直接调用全局函数（在 renderer.js 中定义）
    // 由于这个方法不会被全局包装器覆盖，所以不会递归
    const globalFunc = window['showImportAccountForm'];
    if (globalFunc && globalFunc !== this.showImportAccountForm) {
      globalFunc();
    } else {
      console.error('导入账号功能未找到');
      showCustomAlert('导入功能未加载，请刷新页面重试', 'error');
    }
  },

  /**
   * 显示账号右键菜单
   */
  showAccountContextMenu(event, account) {
    // 移除已存在的菜单
    const existingMenu = document.getElementById('accountContextMenu');
    if (existingMenu) existingMenu.remove();
    
    // 转义账号数据用于 HTML 属性
    const accountJson = JSON.stringify(account).replace(/'/g, '&#39;').replace(/"/g, '&quot;');
    
    const menuHTML = `
      <div id="accountContextMenu" style="position: fixed; background: white; border: 1px solid #e5e5ea; border-radius: 6px; box-shadow: 0 2px 8px rgba(0,0,0,0.12); z-index: 10000; min-width: 140px; visibility: hidden; padding: 4px 0;">
        <div class="context-menu-item" onclick="AccountManager.contextMenuGetToken('${account.id}')" style="color: #007aff;">
          <i data-lucide="key" style="width: 13px; height: 13px;"></i>
          <span>${account.apiKey ? '刷新 Token' : '获取 Token'}</span>
        </div>
        <div class="context-menu-item" onclick="AccountManager.contextMenuEditPassword('${account.id}', '${account.email.replace(/'/g, "\\'")}')">
          <i data-lucide="edit-3" style="width: 13px; height: 13px;"></i>
          <span>修改本地密码</span>
        </div>
        <div class="context-menu-divider"></div>
        <div class="context-menu-item" onclick="AccountManager.contextMenuViewDetails('${account.id}')">
          <i data-lucide="eye" style="width: 13px; height: 13px;"></i>
          <span>查看详情</span>
        </div>
        ${account.refreshToken ? `
        <div class="context-menu-item" onclick="AccountManager.contextMenuRefresh('${account.id}')">
          <i data-lucide="refresh-cw" style="width: 13px; height: 13px;"></i>
          <span>刷新积分</span>
        </div>
        ` : ''}
        <div class="context-menu-divider"></div>
        <div class="context-menu-item" onclick="AccountManager.contextMenuSwitch('${account.id}')">
          <i data-lucide="repeat" style="width: 13px; height: 13px;"></i>
          <span>切换账号</span>
        </div>
        <div class="context-menu-item" onclick="AccountManager.contextMenuExport('${account.id}')">
          <i data-lucide="download" style="width: 13px; height: 13px;"></i>
          <span>导出账号</span>
        </div>
        <div class="context-menu-item" onclick="AccountManager.contextMenuGetPaymentLink('${account.id}')" style="color: #34c759;">
          <i data-lucide="credit-card" style="width: 13px; height: 13px;"></i>
          <span>获取绑卡链接</span>
        </div>
        <div class="context-menu-divider"></div>
        <div class="context-menu-item" onclick="AccountManager.copyToClipboard('${account.email.replace(/'/g, "\\'")}').then(() => { if(typeof showToast === 'function') showToast('邮箱已复制', 'success'); }); AccountManager.closeContextMenu();">
          <i data-lucide="mail" style="width: 13px; height: 13px;"></i>
          <span>复制邮箱</span>
        </div>
        <div class="context-menu-item" onclick="AccountManager.copyToClipboard('${(account.password || '').replace(/'/g, "\\'")}').then(() => { if(typeof showToast === 'function') showToast('密码已复制', 'success'); }); AccountManager.closeContextMenu();">
          <i data-lucide="key" style="width: 13px; height: 13px;"></i>
          <span>复制密码</span>
        </div>
        ${account.apiKey ? `
        <div class="context-menu-item" onclick="AccountManager.copyToClipboard('${account.apiKey.replace(/'/g, "\\'")}').then(() => { if(typeof showToast === 'function') showToast('API Key 已复制', 'success'); }); AccountManager.closeContextMenu();">
          <i data-lucide="code" style="width: 13px; height: 13px;"></i>
          <span>复制 API Key</span>
        </div>
        ` : ''}
        ${account.refreshToken ? `
        <div class="context-menu-item" onclick="AccountManager.copyToClipboard('${account.refreshToken.replace(/'/g, "\\'")}').then(() => { if(typeof showToast === 'function') showToast('Refresh Token 已复制', 'success'); }); AccountManager.closeContextMenu();">
          <i data-lucide="shield" style="width: 13px; height: 13px;"></i>
          <span>复制 Token</span>
        </div>
        ` : ''}
        <div class="context-menu-divider"></div>
        <div class="context-menu-item" style="color: #ff3b30;" onclick="AccountManager.contextMenuDelete('${account.id}', '${account.email.replace(/'/g, "\\'")}')">
          <i data-lucide="trash-2" style="width: 13px; height: 13px;"></i>
          <span>删除账号</span>
        </div>
      </div>
    `;
    
    document.body.insertAdjacentHTML('beforeend', menuHTML);
    
    // 智能定位菜单
    const menu = document.getElementById('accountContextMenu');
    const menuRect = menu.getBoundingClientRect();
    const viewportWidth = window.innerWidth;
    const viewportHeight = window.innerHeight;
    
    let left = event.clientX;
    let top = event.clientY;
    
    // 检查右侧是否超出屏幕
    if (left + menuRect.width > viewportWidth) {
      left = viewportWidth - menuRect.width - 10; // 留10px边距
    }
    
    // 检查底部是否超出屏幕
    if (top + menuRect.height > viewportHeight) {
      top = viewportHeight - menuRect.height - 10; // 留10px边距
    }
    
    // 确保不超出左侧和顶部
    if (left < 10) left = 10;
    if (top < 10) top = 10;
    
    // 应用位置并显示
    menu.style.left = left + 'px';
    menu.style.top = top + 'px';
    menu.style.visibility = 'visible';
    
    if (typeof lucide !== 'undefined') {
      lucide.createIcons();
    }
    
    // 点击其他地方关闭菜单
    setTimeout(() => {
      document.addEventListener('click', function closeMenu() {
        const menu = document.getElementById('accountContextMenu');
        if (menu) menu.remove();
        document.removeEventListener('click', closeMenu);
      });
    }, 100);
  },

  /**
   * 关闭右键菜单
   */
  closeContextMenu() {
    const menu = document.getElementById('accountContextMenu');
    if (menu) menu.remove();
  },

  /**
   * 显示更多操作菜单（点击图标触发）
   */
  showMoreMenu(event, account) {
    event.stopPropagation();
    // 复用右键菜单
    this.showAccountContextMenu(event, account);
  },

  /**
   * 右键菜单 - 获取Token
   */
  async contextMenuGetToken(accountId) {
    const result = await window.ipcRenderer.invoke('get-accounts');
    if (result.success && result.accounts) {
      const account = result.accounts.find(acc => acc.id === accountId);
      if (account) {
        // 创建模拟事件对象
        const mockEvent = {
          stopPropagation: () => {},
          target: {
            closest: () => ({
              getAttribute: (attr) => {
                if (attr === 'data-account') return JSON.stringify(account);
                if (attr === 'data-id') return account.id;
                return null;
              }
            })
          }
        };
        await this.getAccountToken(mockEvent);
      }
    }
    this.closeContextMenu();
  },

  /**
   * 右键菜单 - 修改本地密码
   */
  async contextMenuEditPassword(accountId, email) {
    this.closeContextMenu();
    
    // 使用自定义模态框替代 prompt（Electron 不支持 prompt）
    this.showPasswordEditModal(accountId, email);
  },

  /**
   * 显示修改密码的模态框
   */
  showPasswordEditModal(accountId, email) {
    // 移除已存在的模态框
    const existingModal = document.getElementById('passwordEditModal');
    if (existingModal) existingModal.remove();
    
    const modalHTML = `
      <div id="passwordEditModal" style="position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.5); display: flex; align-items: center; justify-content: center; z-index: 10001;">
        <div style="background: white; border-radius: 12px; padding: 24px; width: 360px; box-shadow: 0 4px 20px rgba(0,0,0,0.15);">
          <h3 style="margin: 0 0 8px 0; font-size: 16px; font-weight: 600;">修改本地密码</h3>
          <p style="margin: 0 0 8px 0; font-size: 13px; color: #666; word-break: break-all;">${email}</p>
          <p style="margin: 0 0 16px 0; font-size: 12px; color: #f59e0b;">⚠️ 仅修改本地保存的密码，不会修改远程账号密码</p>
          <input type="password" id="newPasswordInput" placeholder="请输入新密码（至少6位）" 
            style="width: 100%; padding: 10px 12px; border: 1px solid #ddd; border-radius: 8px; font-size: 14px; box-sizing: border-box; margin-bottom: 16px;">
          <div style="display: flex; gap: 12px; justify-content: flex-end;">
            <button onclick="AccountManager.closePasswordModal()" 
              style="padding: 8px 16px; border: 1px solid #ddd; background: white; border-radius: 6px; cursor: pointer; font-size: 14px;">取消</button>
            <button onclick="AccountManager.submitPasswordChange('${accountId}')" 
              style="padding: 8px 16px; border: none; background: #007aff; color: white; border-radius: 6px; cursor: pointer; font-size: 14px;">确定</button>
          </div>
        </div>
      </div>
    `;
    
    document.body.insertAdjacentHTML('beforeend', modalHTML);
    
    // 聚焦输入框
    setTimeout(() => {
      const input = document.getElementById('newPasswordInput');
      if (input) {
        input.focus();
        // 回车提交
        input.addEventListener('keydown', (e) => {
          if (e.key === 'Enter') {
            this.submitPasswordChange(accountId);
          } else if (e.key === 'Escape') {
            this.closePasswordModal();
          }
        });
      }
    }, 100);
  },

  /**
   * 关闭密码修改模态框
   */
  closePasswordModal() {
    const modal = document.getElementById('passwordEditModal');
    if (modal) modal.remove();
  },

  /**
   * 提交密码修改
   */
  async submitPasswordChange(accountId) {
    const input = document.getElementById('newPasswordInput');
    const newPassword = input ? input.value : '';
    
    if (!newPassword || newPassword.trim().length < 6) {
      showCustomAlert('密码长度至少6位', 'error');
      return;
    }
    
    this.closePasswordModal();
    
    try {
      const result = await window.ipcRenderer.invoke('update-account-password', {
        accountId: accountId,
        newPassword: newPassword.trim()
      });
      
      if (result.success) {
        if (typeof showToast === 'function') {
          showToast('密码修改成功', 'success');
        } else {
          showCustomAlert('密码修改成功', 'success');
        }
        await this.loadAccounts();
      } else {
        showCustomAlert('修改失败: ' + (result.error || '未知错误'), 'error');
      }
    } catch (error) {
      console.error('修改密码失败:', error);
      showCustomAlert('修改失败: ' + error.message, 'error');
    }
  },

  /**
   * 右键菜单 - 查看详情
   */
  async contextMenuViewDetails(accountId) {
    const result = await window.ipcRenderer.invoke('get-accounts');
    if (result.success && result.accounts) {
      const account = result.accounts.find(acc => acc.id === accountId);
      if (account) {
        // 创建模拟事件对象
        const mockEvent = {
          target: {
            closest: () => ({
              getAttribute: (attr) => {
                if (attr === 'data-account') return JSON.stringify(account);
                return null;
              }
            })
          }
        };
        this.viewAccountDetails(mockEvent);
      }
    }
    this.closeContextMenu();
  },

  /**
   * 右键菜单 - 刷新积分
   */
  async contextMenuRefresh(accountId) {
    const result = await window.ipcRenderer.invoke('get-accounts');
    if (result.success && result.accounts) {
      const account = result.accounts.find(acc => acc.id === accountId);
      if (account) {
        const mockEvent = {
          target: {
            closest: () => ({
              getAttribute: (attr) => {
                if (attr === 'data-account') return JSON.stringify(account);
                return null;
              }
            })
          }
        };
        await this.refreshAccountInfo(mockEvent);
      }
    }
    this.closeContextMenu();
  },

  /**
   * 右键菜单 - 切换账号
   */
  async contextMenuSwitch(accountId) {
    if (typeof window.switchToAccount === 'function') {
      await window.switchToAccount(accountId);
    } else {
      console.error('switchToAccount 函数未找到');
      if (typeof showCustomAlert === 'function') {
        showCustomAlert('切换功能暂不可用，请刷新页面重试', 'error');
      }
    }
    this.closeContextMenu();
  },

  /**
   * 右键菜单 - 导出账号
   */
  async contextMenuExport(accountId) {
    const result = await window.ipcRenderer.invoke('get-accounts');
    if (result.success && result.accounts) {
      const account = result.accounts.find(acc => acc.id === accountId);
      if (account) {
        const mockEvent = {
          target: {
            closest: () => ({
              getAttribute: (attr) => {
                if (attr === 'data-account') return JSON.stringify(account);
                return null;
              }
            })
          }
        };
        await this.exportSingleAccount(mockEvent);
      }
    }
    this.closeContextMenu();
  },

  /**
   * 编辑账号备注 - 内联编辑
   */
  editNote(accountId, event) {
    event.stopPropagation();
    
    const cell = event.currentTarget;
    const noteText = cell.querySelector('.note-text');
    const currentNote = noteText ? noteText.textContent : '';
    const displayNote = currentNote === '-' ? '' : currentNote;
    
    // 隐藏文本，显示输入框
    cell.innerHTML = `
      <input type="text" class="note-input" value="${displayNote}" placeholder="输入备注" 
        onblur="AccountManager.saveNoteInline('${accountId}', this)"
        onkeydown="AccountManager.handleNoteKeydown(event, '${accountId}', this)">
    `;
    
    const input = cell.querySelector('.note-input');
    if (input) {
      input.focus();
      input.select();
    }
  },

  /**
   * 处理备注输入框键盘事件
   */
  handleNoteKeydown(event, accountId, input) {
    if (event.key === 'Enter') {
      input.blur(); // 触发保存
    } else if (event.key === 'Escape') {
      // 取消编辑，刷新列表恢复原状
      this.loadAccounts();
    }
  },

  /**
   * 保存账号备注 - 内联保存
   */
  async saveNoteInline(accountId, input) {
    const note = input.value.trim();
    const cell = input.parentElement;
    
    // 先显示保存中状态
    cell.innerHTML = `<span class="note-text" style="color: #86868b;">保存中...</span>`;
    
    const result = await window.ipcRenderer.invoke('update-account-note', accountId, note);
    
    if (result.success) {
      // 更新显示
      cell.innerHTML = `<span class="note-text">${note || '-'}</span>`;
    } else {
      // 失败时刷新列表
      showCustomAlert('保存失败: ' + result.error, 'error');
      await this.loadAccounts();
    }
  },

  /**
   * 右键菜单 - 删除账号
   */
  async contextMenuDelete(accountId, email) {
    this.closeContextMenu();
    
    const confirmed = await showCustomConfirm({
      title: '删除账号',
      message: `确定要删除账号 ${email} 吗？`,
      subMessage: '此操作无法撤销！',
      confirmText: '删除',
      type: 'danger'
    });
    
    if (confirmed) {
      const result = await window.ipcRenderer.invoke('delete-account', accountId);
      if (result.success) {
        if (typeof showToast === 'function') {
          showToast('删除成功！', 'success');
        }
        await this.loadAccounts();
      } else {
        showCustomAlert('删除失败: ' + result.error, 'error');
      }
    }
  },

  /**
   * 显示绑卡链接弹窗
   */
  showPaymentLinkModal(paymentLink) {
    // 移除已存在的弹窗
    const existingModal = document.getElementById('paymentLinkModal');
    if (existingModal) existingModal.remove();
    
    const modalHTML = `
      <div id="paymentLinkModal" class="modal-overlay" style="display: flex;">
        <div class="modal-dialog modern-modal" style="max-width: 500px; width: 90%;" onclick="event.stopPropagation()">
          <div class="modern-modal-header">
            <div class="modal-title-row">
              <i data-lucide="credit-card" style="width: 24px; height: 24px; color: #34c759;"></i>
              <h3 class="modal-title">绑卡链接</h3>
            </div>
            <button class="modal-close-btn" onclick="AccountManager.closePaymentLinkModal()" title="关闭">
              <i data-lucide="x" style="width: 20px; height: 20px;"></i>
            </button>
          </div>
          
          <div class="modern-modal-body">
            <div class="form-group">
              <label>支付链接</label>
              <div style="display: flex; gap: 8px;">
                <input type="text" id="paymentLinkInput" value="${paymentLink}" readonly 
                  style="flex: 1; font-size: 12px; background: #f5f5f7; cursor: text;">
                <button class="btn btn-secondary" onclick="AccountManager.copyPaymentLink()" title="复制">
                  <i data-lucide="copy" style="width: 16px; height: 16px;"></i>
                </button>
              </div>
            </div>
          </div>
          
          <div class="modern-modal-footer">
            <button class="btn btn-secondary" onclick="AccountManager.closePaymentLinkModal()">
              关闭
            </button>
            <button class="btn btn-primary" onclick="AccountManager.openPaymentLink('${paymentLink}')">
              <i data-lucide="external-link" style="width: 16px; height: 16px;"></i>
              打开链接
            </button>
          </div>
        </div>
      </div>
    `;
    
    document.body.insertAdjacentHTML('beforeend', modalHTML);
    
    // 初始化图标
    if (typeof lucide !== 'undefined') {
      lucide.createIcons();
    }
    
    // ESC 关闭
    const escHandler = (e) => {
      if (e.key === 'Escape') {
        this.closePaymentLinkModal();
        document.removeEventListener('keydown', escHandler);
      }
    };
    document.addEventListener('keydown', escHandler);
  },

  /**
   * 关闭绑卡链接弹窗
   */
  closePaymentLinkModal() {
    const modal = document.getElementById('paymentLinkModal');
    if (modal) modal.remove();
  },

  /**
   * 复制绑卡链接
   */
  async copyPaymentLink() {
    const input = document.getElementById('paymentLinkInput');
    if (input) {
      await this.copyToClipboard(input.value);
      if (typeof showCenterMessage === 'function') {
        showCenterMessage('链接已复制', 'success');
      }
    }
  },

  /**
   * 打开绑卡链接
   */
  openPaymentLink(url) {
    window.ipcRenderer.invoke('open-external-url', url);
    this.closePaymentLinkModal();
  },

  /**
   * 右键菜单 - 获取绑卡链接
   */
  async contextMenuGetPaymentLink(accountId) {
    this.closeContextMenu();
    
    const result = await window.ipcRenderer.invoke('get-accounts');
    if (!result || !result.success) return;
    
    const account = result.accounts.find(acc => acc.id === accountId);
    if (!account) return;
    
    // 显示加载提示
    if (typeof showCenterMessage === 'function') {
      showCenterMessage('正在获取绑卡链接...', 'info', 0);
    }
    
    try {
      // 调用 IPC 获取支付链接
      const linkResult = await window.ipcRenderer.invoke('get-payment-link', {
        email: account.email,
        password: account.password
      });
      
      // 移除加载提示
      const existing = document.querySelector('.center-message-overlay');
      if (existing) existing.remove();
      
      if (linkResult.success && linkResult.paymentLink) {
        // 显示自定义弹窗
        this.showPaymentLinkModal(linkResult.paymentLink);
      } else {
        // 失败
        if (typeof showCenterMessage === 'function') {
          showCenterMessage(linkResult.error || '获取绑卡链接失败', 'error', 5000);
        }
      }
    } catch (error) {
      const existing = document.querySelector('.center-message-overlay');
      if (existing) existing.remove();
      
      if (typeof showCenterMessage === 'function') {
        showCenterMessage('获取绑卡链接失败: ' + error.message, 'error', 5000);
      }
    }
  },

  /**
   * 获取账号 Token（用于没有 apiKey 的账号）
   */
  async getAccountToken(event) {
    event.stopPropagation();
    
    const btn = event.target.closest('button');
    if (!btn) return;
    
    const accountId = btn.getAttribute('data-id');
    const accountJson = btn.getAttribute('data-account');
    
    if (!accountJson) {
      showCustomAlert('无法获取账号信息', 'error');
      return;
    }
    
    try {
      const account = JSON.parse(accountJson);
      
      // 打开登录获取 Token 弹窗
      this.openLoginTokenModal(account);
      
      // 调用 IPC 获取 Token
      const result = await window.ipcRenderer.invoke('login-and-get-tokens', account);
      
      if (result.success) {
        // 更新状态
        const statusEl = document.getElementById('loginTokenStatus');
        if (statusEl) {
          statusEl.textContent = '成功';
          statusEl.style.color = '#34c759';
        }
        
        // 添加成功日志
        this.addLoginTokenLog('========== Token 获取成功 ==========', 'success');
        this.addLoginTokenLog(`账号: ${result.account.email}`, 'success');
        this.addLoginTokenLog(`用户名: ${result.account.name || '未知'}`, 'success');
        this.addLoginTokenLog('账号信息已更新到本地文件', 'success');
        this.addLoginTokenLog('', 'info');
        
        if (result.account.refreshToken && account.email && account.password) {
          try {
            await window.AccountQuery.getAccessToken(
              result.account.refreshToken,
              account.email,
              account.password
            );
          } catch (e) {
          }
        }
        
        this.addLoginTokenLog('', 'info');
        this.addLoginTokenLog('您可以关闭此窗口了', 'info');
        
        // 刷新账号列表
        await this.loadAccounts();
      } else {
        // 更新状态
        const statusEl = document.getElementById('loginTokenStatus');
        if (statusEl) {
          statusEl.textContent = '失败';
          statusEl.style.color = '#ff3b30';
        }
        
        // 添加失败日志
        this.addLoginTokenLog('========== Token 获取失败 ==========', 'error');
        this.addLoginTokenLog(`错误: ${result.error}`, 'error');
        this.addLoginTokenLog('', 'info');
        this.addLoginTokenLog('请检查账号密码是否正确，然后重试', 'warning');
      }
    } catch (error) {
      console.error('获取 Token 失败:', error);
      
      // 更新状态
      const statusEl = document.getElementById('loginTokenStatus');
      if (statusEl) {
        statusEl.textContent = '错误';
        statusEl.style.color = '#ff3b30';
      }
      
      this.addLoginTokenLog('========== 发生错误 ==========', 'error');
      this.addLoginTokenLog(`错误: ${error.message}`, 'error');
    }
  },

  /**
   * 打开登录获取 Token 弹窗
   */
  openLoginTokenModal(account) {
    const modal = document.getElementById('loginTokenModal');
    const emailEl = document.getElementById('loginTokenEmail');
    const statusEl = document.getElementById('loginTokenStatus');
    const logEl = document.getElementById('loginTokenLog');
    
    if (!modal) return;
    
    // 设置账号信息
    if (emailEl) emailEl.textContent = account.email;
    if (statusEl) {
      statusEl.textContent = '进行中...';
      statusEl.style.color = '#007aff';
    }
    
    // 清空日志
    if (logEl) logEl.innerHTML = '';
    
    // 显示弹窗
    modal.style.display = 'flex';
    
    // 初始化图标
    if (typeof lucide !== 'undefined') {
      lucide.createIcons();
    }
    
    // 监听日志消息
    if (window.ipcRenderer) {
      window.ipcRenderer.on('login-log', (event, message) => {
        this.addLoginTokenLog(message, 'info');
      });
    }
  },

  /**
   * 添加登录 Token 日志
   */
  addLoginTokenLog(message, type = 'info') {
    const logEl = document.getElementById('loginTokenLog');
    if (!logEl) return;
    
    const colors = {
      info: '#a1a1aa',
      success: '#22c55e',
      error: '#ef4444',
      warning: '#f59e0b'
    };
    
    const div = document.createElement('div');
    div.style.color = colors[type] || colors.info;
    div.textContent = message;
    logEl.appendChild(div);
    
    // 自动滚动到底部
    logEl.scrollTop = logEl.scrollHeight;
  },

  /**
   * 显示错误弹窗
   * @param {string} title - 错误标题
   * @param {Array} hints - 可能原因提示列表
   */
  showErrorModal(title, hints = []) {
    // 移除已存在的错误弹窗
    const existingModal = document.getElementById('refreshErrorModal');
    if (existingModal) {
      existingModal.remove();
    }

    // 构建可能原因列表
    let hintsHtml = '';
    if (hints.length > 0) {
      hintsHtml = `
        <div style="margin-top: 16px; padding: 12px; background: #fff3cd; border-radius: 8px; border-left: 4px solid #ffc107;">
          <div style="font-weight: 600; color: #856404; margin-bottom: 8px;">可能原因：</div>
          <ul style="margin: 0; padding-left: 20px; color: #856404;">
            ${hints.map(hint => `<li style="margin-bottom: 4px;">${hint}</li>`).join('')}
          </ul>
        </div>
      `;
    }

    // 固定的额外提示
    const defaultHints = `
      <div style="margin-top: 12px; padding: 12px; background: #e7f3ff; border-radius: 8px; border-left: 4px solid #007aff;">
        <div style="font-weight: 600; color: #0056b3; margin-bottom: 8px;">排查建议：</div>
        <ul style="margin: 0; padding-left: 20px; color: #0056b3;">
          <li style="margin-bottom: 4px;">检查邮箱密码是否正确</li>
          <li style="margin-bottom: 4px;">确认网络连接正常</li>
          <li style="margin-bottom: 4px;">查看服务器是否正常运行</li>
          <li style="margin-bottom: 4px;">打开控制台（F12）查看详细日志</li>
        </ul>
      </div>
    `;

    const modal = document.createElement('div');
    modal.id = 'refreshErrorModal';
    modal.className = 'modal-overlay active';
    modal.style.zIndex = '10000';
    modal.innerHTML = `
      <div class="modal-dialog modern-modal" style="max-width: 500px; width: 90%;" onclick="event.stopPropagation()">
        <div class="modern-modal-header">
          <div class="modal-title-row">
            <i data-lucide="alert-circle" style="width: 24px; height: 24px; color: #ff3b30;"></i>
            <h3 style="margin: 0; font-size: 18px; font-weight: 600; color: #1d1d1f;">刷新失败</h3>
          </div>
          <button class="modal-close-btn" onclick="document.getElementById('refreshErrorModal').remove()">
            <i data-lucide="x" style="width: 20px; height: 20px;"></i>
          </button>
        </div>
        <div class="modern-modal-body" style="padding: 20px;">
          <div style="background: #ffebee; padding: 16px; border-radius: 12px; border-left: 4px solid #ff3b30;">
            <div style="display: flex; align-items: flex-start; gap: 12px;">
              <i data-lucide="x-circle" style="width: 20px; height: 20px; color: #ff3b30; flex-shrink: 0; margin-top: 2px;"></i>
              <div style="color: #c62828; font-size: 14px; line-height: 1.5; word-break: break-word;">${title}</div>
            </div>
          </div>
          ${hintsHtml}
          ${defaultHints}
        </div>
        <div class="modern-modal-footer" style="padding: 16px 20px; border-top: 1px solid #e5e5ea; display: flex; justify-content: flex-end;">
          <button onclick="document.getElementById('refreshErrorModal').remove()" 
                  style="padding: 10px 24px; background: #007aff; color: white; border: none; border-radius: 8px; font-size: 14px; font-weight: 500; cursor: pointer; transition: background 0.2s;">
            我知道了
          </button>
        </div>
      </div>
    `;

    document.body.appendChild(modal);

    // 点击遮罩层关闭
    modal.addEventListener('click', (e) => {
      if (e.target === modal) {
        modal.remove();
      }
    });

    // 初始化图标
    if (typeof lucide !== 'undefined') {
      lucide.createIcons();
    }
  }
};

// 导出模块
if (typeof module !== 'undefined' && module.exports) {
  module.exports = AccountManager;
}

// 挂载到全局（用于 HTML onclick 调用）
window.AccountManager = AccountManager;

// 兼容旧的全局函数调用
function loadAccounts() {
  return AccountManager.loadAccounts();
}

function showAddAccountForm() {
  return AccountManager.showAddAccountForm();
}

function hideAddAccountForm() {
  return AccountManager.hideAddAccountForm();
}

function addManualAccount() {
  return AccountManager.addManualAccount();
}

function deleteAllAccounts() {
  return AccountManager.deleteAllAccounts();
}

function exportAccounts(type = 'all') {
  return AccountManager.exportAccounts(type);
}

// ============ 搜索账号功能 ============

// 缓存账号列表用于搜索
let cachedAccountsForSearch = [];

/**
 * 显示搜索弹窗
 */
function showSearchAccountModal() {
  const modal = document.getElementById('searchAccountModal');
  if (modal) {
    modal.classList.add('active');
    const input = document.getElementById('searchAccountInput');
    if (input) {
      input.value = '';
      input.focus();
    }
    // 清空之前的搜索结果
    const resultsEl = document.getElementById('searchResults');
    if (resultsEl) {
      resultsEl.innerHTML = '<div style="color: #86868b; text-align: center; padding: 20px;">输入关键词开始搜索</div>';
    }
    // 预加载账号列表
    loadAccountsForSearch();
    // 初始化图标
    if (typeof lucide !== 'undefined') {
      lucide.createIcons();
    }
  }
}

/**
 * 隐藏搜索弹窗
 */
function hideSearchAccountModal() {
  const modal = document.getElementById('searchAccountModal');
  if (modal) {
    modal.classList.remove('active');
  }
}

/**
 * 加载账号列表用于搜索
 */
async function loadAccountsForSearch() {
  try {
    const result = await window.ipcRenderer.invoke('get-accounts');
    if (result.success && result.accounts) {
      cachedAccountsForSearch = result.accounts.filter(acc => acc && acc.email);
    }
  } catch (error) {
    console.error('加载账号列表失败:', error);
  }
}

/**
 * 执行搜索
 */
function performAccountSearch() {
  const input = document.getElementById('searchAccountInput');
  const resultsEl = document.getElementById('searchResults');
  
  if (!input || !resultsEl) return;
  
  const keyword = input.value.trim().toLowerCase();
  
  if (!keyword) {
    resultsEl.innerHTML = '<div style="color: #86868b; text-align: center; padding: 20px;">输入关键词开始搜索</div>';
    return;
  }
  
  // 搜索匹配的账号
  const matches = cachedAccountsForSearch.filter(acc => {
    const email = (acc.email || '').toLowerCase();
    const type = (acc.type || '').toLowerCase();
    return email.includes(keyword) || type.includes(keyword);
  });
  
  if (matches.length === 0) {
    resultsEl.innerHTML = '<div style="color: #86868b; text-align: center; padding: 20px;">未找到匹配的账号</div>';
    return;
  }
  
  // 渲染搜索结果
  let html = `<div style="color: #86868b; font-size: 12px; margin-bottom: 8px;">找到 ${matches.length} 个匹配账号</div>`;
  
  matches.forEach(acc => {
    const typeColor = getTypeColor(acc.type);
    const credits = acc.credits !== undefined ? acc.credits : '-';
    
    html += `
      <div class="search-result-item" onclick="scrollToAccount('${acc.email}')" style="
        padding: 12px;
        background: var(--background);
        border: 1px solid var(--border);
        border-radius: 8px;
        cursor: pointer;
        transition: all 0.2s;
      " onmouseover="this.style.background='var(--hover)'" onmouseout="this.style.background='var(--background)'">
        <div style="display: flex; justify-content: space-between; align-items: center;">
          <div style="flex: 1; min-width: 0;">
            <div style="font-weight: 500; color: var(--text-primary); overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${acc.email}</div>
            <div style="font-size: 12px; color: #86868b; margin-top: 4px;">
              <span style="color: ${typeColor}; font-weight: 500;">${acc.type || '-'}</span>
              <span style="margin: 0 8px;">•</span>
              <span>积分: ${credits}</span>
            </div>
          </div>
          <i data-lucide="chevron-right" style="width: 16px; height: 16px; color: #86868b;"></i>
        </div>
      </div>
    `;
  });
  
  resultsEl.innerHTML = html;
  
  // 刷新图标
  if (typeof lucide !== 'undefined') {
    lucide.createIcons();
  }
}

/**
 * 获取类型对应的颜色
 */
function getTypeColor(type) {
  const typeLower = (type || '').toLowerCase();
  if (typeLower.includes('pro')) return '#007aff';
  if (typeLower.includes('enterprise')) return '#5856d6';
  if (typeLower.includes('team')) return '#ff9500';
  if (typeLower.includes('trial')) return '#34c759';
  if (typeLower.includes('free')) return '#8e8e93';
  return '#999';
}

/**
 * 滚动到指定账号
 */
function scrollToAccount(email) {
  hideSearchAccountModal();
  
  // 查找账号行
  const row = document.querySelector(`.account-item[data-email="${email}"]`);
  if (row) {
    // 滚动到该行
    row.scrollIntoView({ behavior: 'smooth', block: 'center' });
    
    // 高亮效果
    row.style.transition = 'background-color 0.3s';
    row.style.backgroundColor = 'rgba(0, 122, 255, 0.15)';
    
    setTimeout(() => {
      row.style.backgroundColor = '';
    }, 2000);
  } else {
    showToast('未找到该账号，可能已被删除', 'warning');
  }
}

/**
 * 清除搜索并显示全部
 */
function clearSearchAndShowAll() {
  hideSearchAccountModal();
  // 重新加载账号列表
  if (typeof AccountManager !== 'undefined' && AccountManager.loadAccounts) {
    AccountManager.loadAccounts();
  }
}

// 注意：showImportAccountForm 在 renderer.js 中已有实现
// 不需要在这里创建包装器，避免覆盖原有实现

// ============ 自定义确认弹窗 ============

// 确认回调函数
let confirmResolve = null;

/**
 * 显示自定义确认弹窗
 * 支持两种调用方式：
 * 1. showCustomConfirm({ title, message, subMessage, confirmText, type })
 * 2. showCustomConfirm(message, title) - 兼容旧版本
 * @returns {Promise<boolean>} - 用户确认返回 true，取消返回 false
 */
function showCustomConfirm(optionsOrMessage, titleParam) {
  // 兼容旧版本调用方式: showCustomConfirm(message, title)
  let options = {};
  if (typeof optionsOrMessage === 'string') {
    options = {
      title: titleParam || '确认',
      message: optionsOrMessage,
      subMessage: false,
      confirmText: '确定',
      type: 'info'
    };
  } else {
    options = optionsOrMessage || {};
  }
  
  return new Promise((resolve) => {
    confirmResolve = resolve;
    
    const modal = document.getElementById('customConfirmModal');
    const title = document.getElementById('confirmTitle');
    const message = document.getElementById('confirmMessage');
    const subMessage = document.getElementById('confirmSubMessage');
    const actionText = document.getElementById('confirmActionText');
    const actionBtn = document.getElementById('confirmActionBtn');
    const iconContainer = document.getElementById('confirmIconContainer');
    
    // 设置内容
    if (title) title.textContent = options.title || '确认操作';
    if (message) message.textContent = options.message || '确定要执行此操作吗？';
    if (subMessage) {
      subMessage.textContent = options.subMessage || '此操作无法撤销！';
      subMessage.style.display = options.subMessage === false ? 'none' : 'block';
    }
    if (actionText) actionText.textContent = options.confirmText || '确定';
    
    // 根据类型设置颜色
    const type = options.type || 'danger';
    const colors = {
      danger: { bg: 'linear-gradient(135deg, #ff3b30 0%, #ff6b6b 100%)', text: '#ff3b30' },
      warning: { bg: 'linear-gradient(135deg, #ff9500 0%, #ffb84d 100%)', text: '#ff9500' },
      info: { bg: 'linear-gradient(135deg, #007aff 0%, #5ac8fa 100%)', text: '#007aff' }
    };
    const color = colors[type] || colors.danger;
    
    if (iconContainer) iconContainer.style.background = color.bg;
    if (actionBtn) actionBtn.style.background = color.bg;
    if (subMessage) subMessage.style.color = color.text;
    
    // 显示弹窗
    if (modal) {
      modal.classList.add('active');
      // 初始化图标
      if (typeof lucide !== 'undefined') {
        lucide.createIcons();
      }
    }
  });
}

/**
 * 处理确认操作
 */
function handleConfirmAction() {
  const modal = document.getElementById('customConfirmModal');
  if (modal) modal.classList.remove('active');
  if (confirmResolve) {
    confirmResolve(true);
    confirmResolve = null;
  }
}

/**
 * 处理取消操作
 */
function handleConfirmCancel() {
  const modal = document.getElementById('customConfirmModal');
  if (modal) modal.classList.remove('active');
  if (confirmResolve) {
    confirmResolve(false);
    confirmResolve = null;
  }
}

// 👇 必须把这些函数挂载到 window 对象上，HTML 里的按钮才能找到它们
window.batchGetAllTokens = batchGetAllTokens;
window.refreshAllData = refreshAllData;
window.showImportAccountForm = showImportAccountForm;
window.showAddAccountForm = showAddAccountForm; // 预防万一，这个可能也需要