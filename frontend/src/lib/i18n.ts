export const LANG = {
  en: {
    scan: 'Scan',
    scanning: 'Scanning...',
    urlHint: {
      quick: 'Lightweight: headers, TLS, basic patterns.',
      standard: 'Balanced: headers, TLS, domain patterns, behavior.',
      it: 'Deep: full header audit, TLS details, behavior, routing, extended intel.',
    },
    familyMode: {
      off: 'Scanning for someone else? Try Family mode',
      on: 'Family mode: on',
      helper: 'Showing a simpler result with plain-language guidance.',
    },
    empty: {
      title: 'No scans yet',
      body: 'Paste a link above and press Enter to check it.',
      shortcut: 'Keyboard shortcut: focus URL, then Enter',
    },
    social: { uptime: 'Uptime', blocked: 'Scans blocked', free: 'Forever' },
    awareness: { tabSimple: 'Simple', tabDetailed: 'Detailed' },
    nav: { history: 'History', awareness: 'Awareness', api: 'API', status: 'Status' },
    screenshot: { title: 'Screenshot scan', body: 'Upload a photo of a suspicious message and we will extract links automatically.', button: 'Upload image' },
    qr: { title: 'QR scanner', body: 'Scan a QR code to check its link instantly.', button: 'Open camera' },
  },
  ms: {
    scan: 'Imbas',
    scanning: 'Mengimbas...',
    urlHint: {
      quick: 'Ringan: pengepala, TLS, pola asas.',
      standard: 'Seimbang: pengepala, TLS, pola domain, kelakuan.',
      it: 'Mendalam: audit penuh, TLS, kelakuan, laluan, intel lanjutan.',
    },
    familyMode: {
      off: 'Mengimbas untuk orang lain? Cuba mod Keluarga',
      on: 'Mod Keluarga: hidup',
      helper: 'Menunjukkan keputusan lebih ringkas dengan panduan bahasa mudah.',
    },
    empty: {
      title: 'Belum ada imbasan',
      body: 'Tampal pautan di atas dan tekan Enter untuk menyemak.',
      shortcut: 'Pintasan papan kekunci: fokus URL, kemudian Enter',
    },
    social: { uptime: 'Masih aktif', blocked: 'Pihak ketiga disekat', free: 'Percuma' },
    awareness: { tabSimple: 'Ringkas', tabDetailed: 'Terperinci' },
    nav: { history: 'Sejarah', awareness: 'Kesedaran', api: 'API', status: 'Status' },
    screenshot: { title: 'Imbas skrin', body: 'Muat naik foto mesej yang disengat dan kami akan ekstrak pautan secara automatik.', button: 'Muat naik imej' },
    qr: { title: 'Pengimbas QR', body: 'Imbas kod QR untuk menyemak pautan secara serta-merta.', button: 'Buka kamera' },
  },
  zh: {
    scan: '扫描',
    scanning: '扫描中...',
    urlHint: {
      quick: '轻量：标头、TLS、基础规则。',
      standard: '平衡：标头、TLS、域名规则、行为。',
      it: '深度：完整标头审计、TLS 细节、行为、路由、扩展情报。',
    },
    familyMode: {
      off: '替亲友检查？试试家庭模式',
      on: '家庭模式：开启',
      helper: '显示更简单的结果和通俗指导。',
    },
    empty: {
      title: '暂无扫描',
      body: '粘贴链接并按回车检查。',
      shortcut: '快捷键：聚焦 URL 后按 Enter',
    },
    social: { uptime: '运行时间', blocked: '已拦截', free: '永久免费' },
    awareness: { tabSimple: '简版', tabDetailed: '详解' },
    nav: { history: '历史', awareness: '安全常识', api: '接口', status: '状态' },
    screenshot: { title: '截图扫描', body: '上传可疑消息截图，自动提取链接。', button: '上传图片' },
    qr: { title: '二维码扫描', body: '扫描二维码并立即检查链接。', button: '打开相机' },
  },
  ta: {
    scan: 'Scan',
    scanning: 'Scanning...',
    urlHint: {
      quick: 'Quick scan.',
      standard: 'Standard scan.',
      it: 'IT scan.',
    },
    familyMode: {
      off: 'Scanning for someone else? Try Family mode',
      on: 'Family mode: on',
      helper: 'Showing simpler results with plain-language guidance.',
    },
    empty: {
      title: 'No scans yet',
      body: 'Paste a link above and press Enter to check it.',
      shortcut: 'Keyboard shortcut: focus URL, then Enter',
    },
    social: { uptime: 'Uptime', blocked: 'Scans blocked', free: 'Forever' },
    awareness: { tabSimple: 'Simple', tabDetailed: 'Detailed' },
    nav: { history: 'History', awareness: 'Awareness', api: 'API', status: 'Status' },
    screenshot: { title: 'Screenshot scan', body: 'Upload an image to extract links automatically.', button: 'Upload image' },
    qr: { title: 'QR scanner', body: 'Scan a QR code to check its link.', button: 'Open camera' },
  },
} as const;

export type Lang = keyof typeof LANG;
export type LangPack = (typeof LANG)['en'];
