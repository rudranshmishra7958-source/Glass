const HOST_NAME = "com.safebox.browser";

const DANGEROUS_STATES = [
  "content",
  "url",
  "host",
  "file",
  "unwanted",
  "blockedTooLarge",
  "sensitiveContentBlock",
  "accountCompromise"
];

const MAX_MANUAL_FILE_SIZE = 100 * 1024;

const state = {
  recent: [],
  lastReport: null
};


/* =========================================================
   INITIAL STATE
========================================================= */

async function loadState() {
  const data = await chrome.storage.local.get([
    "recent",
    "lastReport"
  ]);

  state.recent =
    Array.isArray(data.recent)
      ? data.recent
      : [];

  state.lastReport =
    data.lastReport || null;
}


async function saveState() {
  await chrome.storage.local.set({
    recent: state.recent.slice(0, 20),
    lastReport: state.lastReport
  });
}


/* =========================================================
   HELPERS
========================================================= */

function getFilename(path) {
  if (!path) {
    return "Unknown file";
  }

  return (
    path.split(/[\\/]/).pop() ||
    "Unknown file"
  );
}


function getRisk(report) {
  return (
    report?.assessment?.risk ||
    "UNKNOWN"
  );
}


function isDangerous(report) {
  const risk =
    getRisk(report);

  return (
    risk === "CRITICAL" ||
    risk === "HIGH"
  );
}


/* =========================================================
   STORE RESULTS
========================================================= */

async function storeReport({
  filename,
  report,
  downloadId = null,
  url = "",
  action = "scanned"
}) {

  const item = {
    downloadId,

    filename,

    url,

    scannedAt:
      new Date().toISOString(),

    risk:
      getRisk(report),

    score:
      report?.assessment?.score ??
      0,

    action,

    report
  };

  state.lastReport = item;

  state.recent.unshift(
    item
  );

  state.recent =
    state.recent.slice(0, 20);

  await saveState();

  return item;
}


/* =========================================================
   NATIVE HOST
========================================================= */

function connectNative(request) {

  return new Promise(
    (resolve, reject) => {

      let completed = false;

      let port;

      try {

        port =
          chrome.runtime.connectNative(
            HOST_NAME
          );

      } catch (error) {

        reject(error);

        return;
      }


      function finish(
        callback,
        value
      ) {

        if (completed) {
          return;
        }

        completed = true;

        try {
          port.disconnect();
        } catch (_) {}

        callback(value);
      }


      port.onMessage.addListener(
        (message) => {

          console.log(
            "SafeBox native response:",
            message
          );

          finish(
            resolve,
            message
          );
        }
      );


      port.onDisconnect.addListener(
        () => {

          if (completed) {
            return;
          }

          const error =
            chrome.runtime.lastError;

          finish(
            reject,
            new Error(
              error?.message ||
              "SafeBox native host disconnected."
            )
          );
        }
      );


      try {

        port.postMessage(
          request
        );

      } catch (error) {

        finish(
          reject,
          error
        );
      }
    }
  );
}


/* =========================================================
   SAVE BROWSER-BLOCKED DOWNLOAD
========================================================= */

async function saveBrowserBlocked(
  download,
  danger
) {

  const blocked = {

    downloadId:
      download.id,

    filename:
      getFilename(
        download.filename
      ),

    danger,

    url:
      download.finalUrl ||
      download.url ||
      "",

    blockedAt:
      new Date().toISOString(),

    report: null
  };


  await chrome.storage.local.set({
    browserBlocked:
      blocked
  });


  return blocked;
}


/* =========================================================
   HANDLE CHROME DANGEROUS DOWNLOAD
========================================================= */

async function handleDangerousDownload(
  download,
  danger
) {

  console.warn(
    "SafeBox: Chrome flagged download:",
    download.filename,
    danger
  );


  try {

    /*
     * Ask Chrome to cancel the download.
     *
     * This is only the Chrome-side danger signal.
     * SafeBox cannot run ClamAV against bytes Chrome
     * never makes available to us.
     */

    await chrome.downloads.cancel(
      download.id
    );

  } catch (error) {

    console.warn(
      "SafeBox: cancel failed:",
      error
    );
  }


  const blocked =
    await saveBrowserBlocked(
      download,
      danger
    );


  /*
   * Build a visible SafeBox report even when Chrome
   * removed the actual file before SafeBox could scan it.
   */

  const report = {

    status: "completed",

    file: {
      name:
        getFilename(
          download.filename
        ),

      path:
        download.filename ||
        "",

      exists: false,

      size: null,

      mime_type:
        download.mime ||
        "unknown"
    },

    static_analysis: {

      clamav: {
        status: "not_scanned",
        detected: false,
        raw:
          "Chrome blocked the download before SafeBox could scan the file."
      },

      yara: {
        status: "not_scanned",
        matches: []
      },

      heuristics: []
    },

    dynamic_analysis: {

      status: "skipped",

      reason:
        "Automatic browser-download analysis does not execute files."
    },

    quarantine: null,

    browser: {

      download_id:
        download.id,

      danger,

      url:
        download.url ||
        "",

      final_url:
        download.finalUrl ||
        "",

      mime:
        download.mime ||
        ""
    },

    assessment: {

      risk: "CRITICAL",

      score: 100,

      reason:
        `Chrome reported this download as dangerous: ${danger}.`,

      evidence: [

        {
          source: "CHROME",

          message:
            `Chrome danger state: ${danger}`
        }

      ]
    }
  };


  blocked.report =
    report;


  await chrome.storage.local.set({
    browserBlocked:
      blocked
  });


  await storeReport({

    filename:
      blocked.filename,

    report,

    downloadId:
      download.id,

    url:
      blocked.url,

    action:
      "browser_blocked"
  });


  console.log(
    "SafeBox: Chrome dangerous download blocked:",
    blocked.filename
  );
}


/* =========================================================
   DOWNLOAD CREATED
========================================================= */

chrome.downloads.onCreated.addListener(
  async (download) => {

    if (
      !download ||
      download.id === undefined
    ) {
      return;
    }


    /*
     * Sometimes the initial object already contains
     * the danger state.
     */

    const danger =
      download.danger;


    if (
      !DANGEROUS_STATES.includes(
        danger
      )
    ) {
      return;
    }


    try {

      await handleDangerousDownload(
        download,
        danger
      );

    } catch (error) {

      console.error(
        "SafeBox onCreated error:",
        error
      );
    }
  }
);


/* =========================================================
   DOWNLOAD CHANGED
========================================================= */

chrome.downloads.onChanged.addListener(
  async (delta) => {

    /*
     * -----------------------------------------------------
     * Chrome danger-state change
     * -----------------------------------------------------
     */

    if (
      delta.danger &&
      DANGEROUS_STATES.includes(
        delta.danger.current
      )
    ) {

      try {

        const results =
          await chrome.downloads.search({
            id: delta.id
          });


        if (
          !results.length
        ) {
          return;
        }


        const download =
          results[0];


        await handleDangerousDownload(
          download,
          delta.danger.current
        );


      } catch (error) {

        console.error(
          "SafeBox danger-state handling failed:",
          error
        );
      }


      return;
    }


    /*
     * -----------------------------------------------------
     * Normal completed download
     * -----------------------------------------------------
     */

    if (
      !delta.state ||
      delta.state.current !==
        "complete"
    ) {
      return;
    }


    try {

      const results =
        await chrome.downloads.search({
          id: delta.id
        });


      if (
        !results.length
      ) {
        return;
      }


      const download =
        results[0];


      /*
       * Do not scan a file that Chrome itself marked
       * dangerous. Its danger handler above already
       * handled the event.
       */

      if (
        DANGEROUS_STATES.includes(
          download.danger
        )
      ) {
        return;
      }


      await scanDownload(
        download
      );


    } catch (error) {

      console.error(
        "SafeBox completed-download scan failed:",
        error
      );

      await chrome.storage.local.set({

        lastScanError: {

          filename:
            getFilename(
              error.filename ||
              "download"
            ),

          error:
            error.message ||
            String(error),

          at:
            new Date().toISOString()
        }
      });
    }
  }
);


/* =========================================================
   SCAN A NORMAL COMPLETED DOWNLOAD
========================================================= */

async function scanDownload(
  download
) {

  if (
    !download ||
    !download.filename
  ) {
    return;
  }


  const filename =
    getFilename(
      download.filename
    );


  console.log(
    "SafeBox: scanning:",
    download.filename
  );


  /*
   * First check whether the path still exists.
   *
   * This prevents the exact FileNotFoundError shown
   * in your screenshot.
   */

  if (
    !download.filename
  ) {

    console.warn(
      "SafeBox: download filename unavailable."
    );

    return;
  }


  try {

    const report =
      await connectNative({

        action: "scan",

        download: {

          id:
            download.id,

          filename:
            download.filename,

          url:
            download.url ||
            "",

          finalUrl:
            download.finalUrl ||
            "",

          mime:
            download.mime ||
            "",

          danger:
            download.danger ||
            "safe"
        }
      });


    if (!report) {

      throw new Error(
        "SafeBox returned no scan report."
      );
    }


    if (
      report.status ===
      "error"
    ) {

      throw new Error(
        report.error ||
        "SafeBox scanner returned an error."
      );
    }


    console.log(
      "SafeBox native response:",
      report
    );


    /*
     * Safe/clean file.
     */

    if (
      !isDangerous(
        report
      )
    ) {

      const item =
        await storeReport({

          filename,

          report,

          downloadId:
            download.id,

          url:
            download.finalUrl ||
            download.url ||
            "",

          action:
            "clean"
        });


      console.log(
        "SafeBox scan result:",
        item
      );


      return item;
    }


    /*
     * High/Critical file.
     *
     * At this point the file has reached the local
     * Downloads directory, so remove it.
     */

    let removed =
      false;


    try {

      await chrome.downloads.removeFile(
        download.id
      );

      removed = true;

    } catch (error) {

      console.warn(
        "SafeBox: unable to remove malicious file:",
        error
      );
    }


    const item =
      await storeReport({

        filename,

        report,

        downloadId:
          download.id,

        url:
          download.finalUrl ||
          download.url ||
          "",

        action:
          removed
            ? "blocked_and_deleted"
            : "blocked"
      });


    console.warn(
      "SafeBox threat result:",
      item
    );


    return item;

  } catch (error) {

    console.error(
      "SafeBox completed-download scan failed:",
      error
    );

    throw error;
  }
}


/* =========================================================
   MANUAL FILE SCAN
========================================================= */

async function scanSelectedFile(
  file
) {

  if (
    !file ||
    !file.base64
  ) {
    throw new Error(
      "No file data supplied."
    );
  }


  if (
    file.size >
    MAX_MANUAL_FILE_SIZE
  ) {
    throw new Error(
      "File exceeds the 100 KB manual scan limit."
    );
  }


  console.log(
    "SafeBox: manually scanning:",
    file.name
  );


  const report =
    await connectNative({

      action:
        "scan_bytes",

      file: {

        name:
          file.name ||
          "selected_file",

        size:
          file.size ||
          0,

        mimeType:
          file.mimeType ||
          "application/octet-stream",

        base64:
          file.base64
      }
    });


  if (!report) {

    throw new Error(
      "SafeBox returned no scan report."
    );
  }


  if (
    report.status ===
    "error"
  ) {

    throw new Error(
      report.error ||
      "Manual scan failed."
    );
  }


  const item =
    await storeReport({

      filename:
        file.name ||
        "selected_file",

      report,

      downloadId:
        null,

      url:
        "",

      action:
        "manual_scan"
    });


  return item;
}


/* =========================================================
   POPUP MESSAGE HANDLER
========================================================= */

chrome.runtime.onMessage.addListener(
  (
    message,
    sender,
    sendResponse
  ) => {


    /*
     * -----------------------------------------------------
     * GET STATE
     * -----------------------------------------------------
     */

    if (
      message?.type ===
      "getState"
    ) {

      (async () => {

        try {

          await loadState();


          const data =
            await chrome.storage.local.get([
              "browserBlocked",
              "lastScanError"
            ]);


          sendResponse({

            recent:
              state.recent,

            lastReport:
              state.lastReport,

            browserBlocked:
              data.browserBlocked ||
              null,

            lastScanError:
              data.lastScanError ||
              null
          });


        } catch (error) {

          sendResponse({

            recent: [],

            lastReport: null,

            browserBlocked: null,

            lastScanError: {

              error:
                error.message ||
                String(error)
            }
          });
        }

      })();


      return true;
    }


    /*
     * -----------------------------------------------------
     * MANUAL FILE SCAN
     * -----------------------------------------------------
     */

    if (
      message?.type ===
      "scanSelectedFile"
    ) {

      scanSelectedFile(
        message.file
      )
        .then(
          (item) => {

            sendResponse({

              ok: true,

              item
            });
          }
        )
        .catch(
          (error) => {

            console.error(
              "SafeBox manual scan failed:",
              error
            );

            sendResponse({

              ok: false,

              error:
                error.message ||
                String(error)
            });
          }
        );


      return true;
    }


    /*
     * -----------------------------------------------------
     * DELETE BLOCKED DOWNLOAD
     * -----------------------------------------------------
     */

    if (
      message?.type ===
      "deleteDownload"
    ) {

      (async () => {

        try {

          const id =
            message.downloadId;


          if (
            id === undefined ||
            id === null
          ) {

            throw new Error(
              "Missing download ID."
            );
          }


          try {

            await chrome.downloads.cancel(
              id
            );

          } catch (_) {}


          try {

            await chrome.downloads.removeFile(
              id
            );

          } catch (_) {}


          await chrome.storage.local.remove(
            "browserBlocked"
          );


          const item =
            state.recent.find(
              (entry) =>
                entry.downloadId === id
            );


          if (item) {

            item.action =
              "deleted_by_user";

            await saveState();
          }


          sendResponse({
            ok: true
          });


        } catch (error) {

          sendResponse({

            ok: false,

            error:
              error.message ||
              "Unable to delete download."
          });
        }

      })();


      return true;
    }


    /*
     * -----------------------------------------------------
     * DOWNLOAD ANYWAY
     * -----------------------------------------------------
     */

    if (
      message?.type ===
      "allowDownload"
    ) {

      (async () => {

        try {

          const id =
            message.downloadId;


          if (
            id === undefined ||
            id === null
          ) {

            throw new Error(
              "Missing download ID."
            );
          }


          /*
           * Chrome only permits acceptDanger() for
           * downloads that are still available to Chrome
           * as dangerous downloads.
           *
           * This is intentionally user-triggered from
           * the popup.
           */

          await chrome.downloads.acceptDanger(
            id
          );


          await chrome.storage.local.remove(
            "browserBlocked"
          );


          const item =
            state.recent.find(
              (entry) =>
                entry.downloadId === id
            );


          if (item) {

            item.action =
              "allowed_by_user";

            await saveState();
          }


          sendResponse({
            ok: true
          });


        } catch (error) {

          console.error(
            "SafeBox allowDownload failed:",
            error
          );


          sendResponse({

            ok: false,

            error:
              error.message ||
              "Chrome could not restore this download."
          });
        }

      })();


      return true;
    }


    return false;
  }
);


/* =========================================================
   STARTUP
========================================================= */

loadState()
  .catch(
    (error) => {

      console.error(
        "SafeBox startup state error:",
        error
      );
    }
  );
