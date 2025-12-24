const Imap = require('imap');
const { simpleParser } = require('mailparser');
const iconv = require('iconv-lite');

/**
 * 本地邮箱验证码接收器
 */
// 检测是否为乱码文本（简单启发式）
function isGarbledText(text) {
  if (!text || text.length < 10) return false;
  // 检测常见乱码特征：连续的问号、方块字符、或高比例的不可打印字符
  const garbledPatterns = /[\ufffd\u0000-\u001f]{3,}|\?{5,}/;
  const nonPrintableRatio = (text.match(/[\x00-\x1f\x7f-\x9f]/g) || []).length / text.length;
  return garbledPatterns.test(text) || nonPrintableRatio > 0.1;
}

class EmailReceiver {
  constructor(config, logCallback = null) {
    this.config = config;
    this.log = typeof logCallback === 'function' ? logCallback : console.log;

    // 强制优化为 QQ 邮箱 IMAP 配置
    // 即使外部传入其他 host/port，这里也统一为 QQ 的设置
    this.config.host = 'imap.qq.com';
    this.config.port = 993;
  }

  /**
   * 获取所有可用的邮箱列表（用于检测垃圾箱）
   */
  async getMailboxList(imap) {
    return new Promise((resolve) => {
      imap.getBoxes((err, boxes) => {
        if (err) {
          this.log(`获取邮箱列表失败: ${err.message}`);
          resolve([]);
          return;
        }
        
        const boxNames = [];
        const extractBoxNames = (boxes, prefix = '') => {
          for (const name in boxes) {
            const fullName = prefix ? `${prefix}${boxes[name].delimiter || '/'}${name}` : name;
            boxNames.push(fullName);
            if (boxes[name].children) {
              extractBoxNames(boxes[name].children, fullName);
            }
          }
        };
        
        extractBoxNames(boxes);
        resolve(boxNames);
      });
    });
  }

  /**
   * 获取验证码（优化的IMAP实现，支持垃圾箱）
   */
  async getVerificationCode(targetEmail, maxWaitTime = 120000) {
    return new Promise((resolve, reject) => {
      const startTime = Date.now();
      this.log(`开始通过 IMAP 获取验证码，目标邮箱: ${targetEmail}`);
      this.log(`IMAP 服务器: ${this.config.host}:${this.config.port} (仅支持 QQ 邮箱)`);
      
      // 创建IMAP连接
      const imap = new Imap({
        user: this.config.user,
        password: this.config.password,
        host: this.config.host,
        port: this.config.port || 993,
        tls: true,
        tlsOptions: { rejectUnauthorized: false },
        connTimeout: 120000, // 连接超时120秒
        authTimeout: 120000, // 认证超时120秒
        keepalive: {
          interval: 10000,
          idleInterval: 300000,
          forceNoop: true
        }
      });

      let checkInterval;
      let isResolved = false;
      let currentBox = null; // 当前打开的邮箱
      let junkBoxChecked = false; // 是否已检查过垃圾箱
      const processedEmails = new Set(); // 记录已处理的邮件ID

      // 清理资源
      const cleanup = () => {
        if (checkInterval) {
          clearInterval(checkInterval);
          checkInterval = null;
        }
        if (imap.state !== 'disconnected') {
          try {
            imap.end();
          } catch (e) {
            // 忽略关闭错误
          }
        }
      };

      // 处理单封邮件
      const processEmail = async (parsed, emailId) => {
        if (isResolved || processedEmails.has(emailId)) return false;
        
        processedEmails.add(emailId);

        const subject = parsed.subject || '';
        const from = parsed.from?.text || '';
        const to = parsed.to?.text || '';
        const date = parsed.date || new Date();
        
        this.log(`邮件 #${emailId} - 主题: ${subject}, 发件人: ${from}, 时间: ${date}`);
        this.log(`[DEBUG] 邮件 #${emailId} - 收件人: ${to}`);
        this.log(`[DEBUG] 邮件 #${emailId} - Content-Type: ${parsed.headers?.get('content-type') || 'unknown'}`);
        
        // 检查邮件时间，只处理最近2分钟内的邮件
        const emailAge = Date.now() - new Date(date).getTime();
        const maxEmailAge = 2 * 60 * 1000; // 2分钟
        if (emailAge > maxEmailAge) {
          this.log(`邮件过旧（${Math.floor(emailAge/1000)}秒前），跳过`);
          return false;
        }
        
        // 检查是否为Windsurf验证邮件
        const subjectLower = subject.toLowerCase();
        const fromLower = from.toLowerCase();
        
        const isWindsurfEmail = 
          subjectLower.includes('windsurf') || 
          subjectLower.includes('verify') ||
          subjectLower.includes('verification') ||
          fromLower.includes('windsurf') ||
          fromLower.includes('codeium') ||
          fromLower.includes('exafunction');
        
        if (!isWindsurfEmail) {
          this.log('不是 Windsurf 验证邮件，跳过');
          return false;
        }
        
        // 验证码匹配模式（按优先级排序，更精确的在前）
        const patterns = [
          // Windsurf 特定格式
          /following\s+6\s*-?\s*digit\s+code[^\d]*(\d{6})/i,
          /enter\s+(?:the\s+)?following[^\d]*(\d{6})/i,
          // 通用验证码格式
          /verification\s*code[：:\s]*([A-Z0-9]{6})/i,
          /verify\s*code[：:\s]*([A-Z0-9]{6})/i,
          /code\s*(?:is)?[：:\s]+([A-Z0-9]{6})/i,
          /your\s*code[：:\s]*([A-Z0-9]{6})/i,
          // 中文格式（支持全角/半角冒号和空格）
          /验证码[：:\s\u3000]*([A-Z0-9]{6})/i,
          /验证代码[：:\s\u3000]*([A-Z0-9]{6})/i,
          /code[：:\s]*([A-Z0-9]{6})(?![0-9])/i,
          // 独立的6位数字（更严格：排除日期、电话等场景）
          /(?:^|[^0-9])([0-9]{6})(?:[^0-9]|$)/
        ];
        
        // 优先从主题提取验证码（最快，无需解析内容）
        // 支持格式: "123456 - xxx" 或 "xxx - 123456" 或 "Verify xxx 123456"
        const subjectMatch = subject.match(/(?:^|[\s\-:])([0-9]{6})(?:[\s\-]|$)/);
        if (subjectMatch) {
          cleanup();
          if (!isResolved) {
            isResolved = true;
            this.log(`成功从邮件主题提取验证码: ${subjectMatch[1]}`);
            resolve(subjectMatch[1]);
          }
          return true;
        }
        
        this.log('主题中未找到验证码，开始从邮件内容提取');
        
        // 方案1: 优先从纯文本提取（最快）
        if (parsed.text) {
          this.log(`[DEBUG] 纯文本内容(前200字符): ${parsed.text.substring(0, 200).replace(/\n/g, '\\n')}`);
          const textLower = parsed.text.toLowerCase();
          const emailDomain = targetEmail.split('@')[0];
          const isTargetEmail = to.includes(targetEmail) || 
                               textLower.includes(targetEmail.toLowerCase()) ||
                               textLower.includes(emailDomain.toLowerCase());
          
          if (!isTargetEmail) {
            this.log(`收件人不匹配（text），目标: ${targetEmail}`);
            return false;
          }
          
          this.log('从纯文本内容提取验证码');
          for (const pattern of patterns) {
            const match = parsed.text.match(pattern);
            if (match) {
              cleanup();
              if (!isResolved) {
                isResolved = true;
                this.log(`成功从纯文本提取验证码: ${match[1]}`);
                resolve(match[1]);
              }
              return true;
            }
          }
        }
        
        // 方案2: 如果纯文本没有，直接从HTML原文匹配（快速，不清理）
        if (parsed.html) {
          this.log('纯文本未找到，尝试从HTML原文提取');
          // 去除HTML标签后打印内容便于调试
          const htmlTextOnly = parsed.html.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
          this.log(`[DEBUG] HTML文本内容(前200字符): ${htmlTextOnly.substring(0, 200)}`);
          
          const htmlLower = parsed.html.toLowerCase();
          const emailDomain = targetEmail.split('@')[0];
          const isTargetEmail = to.includes(targetEmail) || 
                               htmlLower.includes(targetEmail.toLowerCase()) ||
                               htmlLower.includes(emailDomain.toLowerCase());
          
          if (!isTargetEmail) {
            this.log(`收件人不匹配（html），目标: ${targetEmail}`);
            return false;
          }
          
          // 直接从HTML原文匹配验证码（无需清理HTML标签，速度快）
          for (const pattern of patterns) {
            const match = parsed.html.match(pattern);
            if (match) {
              cleanup();
              if (!isResolved) {
                isResolved = true;
                this.log(`成功从HTML原文提取验证码: ${match[1]}`);
                resolve(match[1]);
              }
              return true;
            }
          }
          
          // 方案3: 如果还是没找到，才进行轻量级HTML清理后再匹配
          this.log('HTML原文未找到，进行轻量级清理后重试');
          const cleanHtml = parsed.html
            .replace(/<style[^>]*>.*?<\/style>/gi, '')
            .replace(/<script[^>]*>.*?<\/script>/gi, '')
            .replace(/<[^>]+>/g, ' ')
            .replace(/&nbsp;/g, ' ')
            .replace(/&#(\d+);/g, (match, dec) => String.fromCharCode(dec))
            .replace(/\s+/g, ' ')
            .trim();
          
          for (const pattern of patterns) {
            const match = cleanHtml.match(pattern);
            if (match) {
              cleanup();
              if (!isResolved) {
                isResolved = true;
                this.log(`成功从清理后的HTML提取验证码: ${match[1]}`);
                resolve(match[1]);
              }
              return true;
            }
          }
        }
        
        this.log('未能从邮件中提取验证码');
        return false;
      };

      // 切换到下一个邮箱（垃圾箱）
      const switchToNextBox = async () => {
        if (isResolved || junkBoxChecked) return;
        
        this.log('收件箱未找到验证码，尝试检查垃圾箱...');
        junkBoxChecked = true;
        
        try {
          // 获取所有邮箱列表
          const allBoxes = await this.getMailboxList(imap);
          this.log(`可用邮箱: ${allBoxes.join(', ')}`);
          
          // 查找垃圾箱（兼容多种命名）
          const junkBoxNames = [
            'Junk',           // 标准命名
            'Spam',           // Gmail
            'Deleted Messages', // QQ邮箱
            'Trash',          // 某些邮箱
            'Bulk Mail',      // Outlook
            '[Gmail]/Spam',   // Gmail IMAP
            'INBOX.Junk',     // 某些IMAP服务器
            'INBOX.Spam'
          ];
          
          let junkBox = null;
          for (const boxName of allBoxes) {
            const lowerBoxName = boxName.toLowerCase();
            if (junkBoxNames.some(junk => lowerBoxName.includes(junk.toLowerCase()))) {
              junkBox = boxName;
              break;
            }
          }
          
          if (!junkBox) {
            this.log('未找到垃圾箱，继续等待收件箱...');
            return;
          }
          
          this.log(`找到垃圾箱: ${junkBox}`);
          
          // 关闭当前邮箱
          imap.closeBox((err) => {
            if (err) {
              this.log(`关闭收件箱失败: ${err.message}`);
            }
            
            // 打开垃圾箱
            imap.openBox(junkBox, false, (err, box) => {
              if (err) {
                this.log(`打开垃圾箱失败: ${err.message}`);
                return;
              }
              
              currentBox = junkBox;
              this.log(`已切换到垃圾箱: ${junkBox}`);
              
              // 立即检查垃圾箱中的邮件
              checkMail();
            });
          });
        } catch (error) {
          this.log(`切换垃圾箱失败: ${error.message}`);
        }
      };

      // 检查邮件
      const checkMail = () => {
        if (isResolved) return;
        
        if (Date.now() - startTime > maxWaitTime) {
          cleanup();
          if (!isResolved) {
            isResolved = true;
            const msg = '获取验证码超时：在指定时间内未找到有效验证码邮件';
            this.log(msg);
            reject(new Error(msg));
          }
          return;
        }

        if (!currentBox) {
          this.log('等待邮箱打开...');
          return;
        }

        // 构建搜索条件：优先搜索最近5分钟内的未读邮件
        // 如果多次搜索无结果，扩大到已读邮件（防止被其他客户端标记已读）
        const sinceDate = new Date(Date.now() - 5 * 60 * 1000); // 5分钟前
        const searchCriteria = [
          ['SINCE', sinceDate],
          'UNSEEN'
        ];

        this.log(`[DEBUG] 搜索条件: SINCE ${sinceDate.toISOString()}, UNSEEN`);
        this.log(`[DEBUG] 当前邮箱: ${currentBox}`);

        imap.search(searchCriteria, (err, results) => {
          if (err) {
            this.log(`搜索邮件失败: ${err.message}`);
            return;
          }

          this.log(`[DEBUG] UNSEEN 搜索结果: ${results ? results.length : 0} 封邮件, IDs: ${results ? results.slice(0, 5).join(',') : 'none'}`);

          if (!results || results.length === 0) {
            // Fallback: 搜索已读邮件（可能被其他客户端标记已读）
            this.log(`[DEBUG] UNSEEN 无结果，尝试 fallback 搜索所有最近邮件...`);
            const fallbackCriteria = [['SINCE', sinceDate]];
            imap.search(fallbackCriteria, (fallbackErr, fallbackResults) => {
              this.log(`[DEBUG] Fallback 搜索结果: ${fallbackResults ? fallbackResults.length : 0} 封邮件`);
              if (fallbackErr || !fallbackResults || fallbackResults.length === 0) {
                // 如果收件箱没有邮件且未检查垃圾箱，则切换到垃圾箱
                if (currentBox === 'INBOX' && !junkBoxChecked) {
                  const elapsedTime = Date.now() - startTime;
                  // 在收件箱等待30秒后，如果还没找到，就检查垃圾箱
                  if (elapsedTime > 30000) {
                    switchToNextBox();
                  }
                }
                return;
              }
              this.log(`未读邮件为空，尝试搜索已读邮件，发现 ${fallbackResults.length} 封`);
              // 将 fallback 结果合并到主流程处理
              results = fallbackResults;
              processSearchResults(results);
            });
            return;
          }
          
          processSearchResults(results);
        });
        
        // 抽取搜索结果处理逻辑
        const processSearchResults = (results) => {
          
          // 过滤掉已处理的邮件
          const newResults = results.filter(id => !processedEmails.has(id));
          if (newResults.length === 0) {
            return;
          }
          
          this.log(`发现 ${newResults.length} 封新邮件，开始检查...`);

          // 按邮件ID倒序处理（最新的邮件ID最大），只处理最新的10封
          const sortedResults = newResults.sort((a, b) => b - a).slice(0, 10);
          
          // 第一步：只获取邮件头（HEADER.FIELDS），速度极快
          const fetch = imap.fetch(sortedResults, { 
            bodies: ['HEADER.FIELDS (FROM TO SUBJECT DATE)'],
            struct: false,
            markSeen: false
          });

          fetch.on('message', (msg, seqno) => {
            let emailId = null;
            let headerParsed = false;
            
            msg.on('attributes', (attrs) => {
              emailId = attrs.uid;
            });
            
            msg.on('body', (stream, info) => {
              // 快速解析邮件头
              simpleParser(stream, async (err, parsed) => {
                if (err || !emailId || isResolved) return;
                
                const subject = parsed.subject || '';
                const from = parsed.from?.text || '';
                const to = parsed.to?.text || '';
                const date = parsed.date || new Date();
                
                // 检查邮件时间
                const emailAge = Date.now() - new Date(date).getTime();
                if (emailAge > 2 * 60 * 1000) {
                  processedEmails.add(emailId);
                  return;
                }
                
                // 检查是否为Windsurf邮件
                const subjectLower = subject.toLowerCase();
                const fromLower = from.toLowerCase();
                const isWindsurf = subjectLower.includes('windsurf') || 
                                  subjectLower.includes('verify') ||
                                  fromLower.includes('windsurf') ||
                                  fromLower.includes('codeium') ||
                                  fromLower.includes('exafunction');
                
                if (!isWindsurf) {
                  processedEmails.add(emailId);
                  return;
                }
                
                this.log(`邮件 #${emailId} - 主题: ${subject}, 收件人: ${to}`);
                
                // 关键：检查收件人是否匹配（防止批量注册时验证码混淆）
                const emailDomain = targetEmail.split('@')[0];
                const isTargetEmail = to.toLowerCase().includes(targetEmail.toLowerCase()) || 
                                     to.toLowerCase().includes(emailDomain.toLowerCase());
                
                if (!isTargetEmail) {
                  this.log(`收件人不匹配，目标: ${targetEmail}，跳过`);
                  processedEmails.add(emailId);
                  return;
                }
                
                this.log(`收件人匹配，目标邮箱: ${targetEmail}`);
                
                // 优先从主题提取验证码（最快路径，90%的情况）
                // 支持格式: "123456 - xxx" 或 "xxx - 123456" 或 "Verify xxx 123456"
                const subjectMatch = subject.match(/(?:^|[\s\-:])([0-9]{6})(?:[\s\-]|$)/);
                if (subjectMatch) {
                  processedEmails.add(emailId);
                  cleanup();
                  if (!isResolved) {
                    isResolved = true;
                    this.log(`成功从邮件主题提取验证码: ${subjectMatch[1]}`);
                    resolve(subjectMatch[1]);
                  }
                  return;
                }
                
                // 如果主题没有验证码，才获取完整邮件体
                this.log('主题无验证码，获取完整邮件...');
                headerParsed = true;
                
                const fullFetch = imap.fetch([emailId], { 
                  bodies: '',
                  markSeen: false
                });
                
                fullFetch.on('message', (fullMsg) => {
                  fullMsg.on('body', (fullStream) => {
                    // 使用增强的编码处理
                    simpleParser(fullStream, {
                      // 设置默认编码 fallback
                      skipHtmlToText: false,
                      skipTextToHtml: false,
                      skipTextLinks: true
                    }, async (err, fullParsed) => {
                      if (err || isResolved) return;
                      
                      // 尝试修复可能的编码问题
                      if (fullParsed.html && isGarbledText(fullParsed.html)) {
                        this.log('检测到可能的编码问题，尝试 GBK 解码...');
                        try {
                          // mailparser 内部已处理大部分编码，这里做额外检查
                        } catch (e) {
                          this.log(`编码修复失败: ${e.message}`);
                        }
                      }
                      
                      await processEmail(fullParsed, emailId);
                    });
                  });
                });
                
                fullFetch.once('error', (err) => {
                  this.log(`获取完整邮件失败: ${err.message}`);
                  processedEmails.add(emailId);
                });
              });
            });
          });

          fetch.once('error', (err) => {
            this.log(`获取邮件内容失败: ${err.message}`);
          });
          
          fetch.once('end', () => {
            // 邮件获取完成
          });
        };

      };

      // IMAP连接成功
      imap.once('ready', () => {
        this.log('IMAP 连接成功');
        
        // 打开收件箱（优先检查）
        imap.openBox('INBOX', false, (err, box) => {
          if (err) {
            cleanup();
            if (!isResolved) {
              isResolved = true;
              reject(new Error(`打开邮箱失败: ${err.message}`));
            }
            return;
          }
          
          currentBox = 'INBOX';
          this.log('收件箱已打开，开始监听验证码邮件...');
          this.log(`目标邮箱: ${targetEmail}`);
          this.log(`最大等待时间: ${maxWaitTime/1000} 秒`);
          this.log('提示: 如果收件箱30秒内未找到，将自动检查垃圾箱');
          
          // 立即检查一次
          checkMail();
          
          // 每2秒检查一次新邮件（更快响应）
          checkInterval = setInterval(checkMail, 2000);
        });
      });

      // IMAP连接错误
      imap.once('error', (err) => {
        cleanup();
        if (!isResolved) {
          isResolved = true;
          const msg = `IMAP 连接失败：${err.message}（请检查 QQ 邮箱 IMAP 是否开启、账号/授权码是否正确）`;
          this.log(msg);
          reject(new Error(msg));
        }
      });

      // IMAP连接关闭
      imap.once('end', () => {
        cleanup();
        this.log('IMAP 连接已关闭');
      });

      // 开始连接
      imap.connect();
    });
  }

  /**
   * 测试IMAP连接
   */
  async testConnection() {
    return new Promise((resolve, reject) => {
      const imap = new Imap({
        user: this.config.user,
        password: this.config.password,
        host: this.config.host,
        port: this.config.port || 993,
        tls: true,
        tlsOptions: { rejectUnauthorized: false }
      });

      imap.once('ready', () => {
        imap.end();
        resolve({ success: true, message: 'IMAP连接成功' });
      });

      imap.once('error', (err) => {
        reject({ success: false, message: `IMAP连接失败: ${err.message}` });
      });

      imap.connect();
    });
  }
}

module.exports = EmailReceiver;
