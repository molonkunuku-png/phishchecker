// background/worker.js
chrome.runtime.onInstalled.addListener(() => {
  console.log('PhishChecker extension installed');
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'scan') {
    return scanUrl(message.url);
  }
  
  return true; // Will respond asynchronously
});

async function scanUrl(url) {
  try {
    // In real use this would call your actual API
    const response = await fetch('https://phishchecker.onrender.com/api/v2/scan', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-PhishChecker-Secret': 'YOUR_API_KEY_HERE'
      },
      body: JSON.stringify({ url })
    });
    
    const data = await response.json();
    return data;
  } catch (error) {
    return { error: 'Scan failed' };
  }
}