// --------------------------------------------------
// KAVACH GUARD - BACKGROUND SERVICE WORKER
// --------------------------------------------------

// Create right-click menu when extension is installed
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "scan-with-kavach",
    title: "🛡 Scan with KAVACH",
    contexts: ["selection"]
  });
});


// When user clicks "Scan with KAVACH"
chrome.contextMenus.onClicked.addListener(
  async (info) => {
    if (
      info.menuItemId === "scan-with-kavach" &&
      info.selectionText
    ) {
      // Store selected text locally
      await chrome.storage.local.set({
        kavachSelectedText: info.selectionText,
        kavachAutoAnalyze: true
      });

      // Try to open KAVACH popup automatically
      try {
        await chrome.action.openPopup();
      } catch (error) {
        console.log(
          "Popup could not open automatically:",
          error
        );
      }
    }
  }
);