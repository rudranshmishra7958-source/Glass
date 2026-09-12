/* =========================================================
 S afeBox* Popup
 ========================================================= */


/* =========================================================
 H elpers*
 ========================================================= */

function setText(
  id,
  value
) {

  const element =
  document.getElementById(id);

  if (!element) {
    return;
  }

  element.textContent =
  value === undefined ||
  value === null ||
  value === ""
  ? "—"
  : String(value);
}


function bytes(
  value
) {

  const number =
  Number(value);

  if (
    !Number.isFinite(number)
  ) {
    return "—";
  }

  if (
    number < 1024
  ) {
    return `${number} B`;
  }

  if (
    number < 1048576
  ) {
    return `${(
      number / 1024
    ).toFixed(1)} KB`;
  }

  return `${(
    number / 1048576
  ).toFixed(1)} MB`;
}


function shortHash(
  hash
) {

  if (!hash) {
    return "—";
  }

  const value =
  String(hash);

  if (
    value.length <= 20
  ) {
    return value;
  }

  return (
    `${value.slice(0, 10)}…${value.slice(-8)}`
  );
}


function riskClass(
  risk
) {

  const classes = {

    LOW:
    "risk-low",

    MEDIUM:
    "risk-medium",

    HIGH:
    "risk-high",

    CRITICAL:
    "risk-critical"

  };


  return (
    classes[risk] ||
    "risk-medium"
  );
}


/* =========================================================
 R ender *blocked download
 ========================================================= */

function renderPending(
  pending
) {

  const panel =
  document.getElementById(
    "pendingPanel"
  );


  if (!panel) {
    return;
  }


  if (!pending) {

    panel.classList.add(
      "hidden"
    );

    return;
  }


  panel.classList.remove(
    "hidden"
  );


  setText(
    "pendingName",
    pending.filename ||
    "Threat detected"
  );


  const reason =
  pending.report?.assessment?.reason ||
  (
    `SafeBox blocked a ${
      pending.danger ||
      "dangerous"
    } download.`
  );


  setText(
    "pendingReason",
    reason
  );


  /* -------------------------------------------------------
   D ownl*oad Anyway
   ------------------------------------------------------- */

  const allowButton =
  document.getElementById(
    "allowPending"
  );


  if (allowButton) {

    allowButton.onclick =
    async () => {

      allowButton.disabled =
      true;


      try {

        const response =
        await chrome.runtime.sendMessage({

          type:
          "allowDownload",

          downloadId:
          pending.downloadId
        });


        if (
          !response?.ok
        ) {

          throw new Error(
            response?.error ||
            "Chrome could not restore the download."
          );
        }


        panel.classList.add(
          "hidden"
        );


        refresh();


      } catch (error) {

        alert(
          `SafeBox: ${error.message}`
        );

      } finally {

        allowButton.disabled =
        false;
      }
    };
  }


  /* -------------------------------------------------------
   D elet*e
   ------------------------------------------------------- */

  const deleteButton =
  document.getElementById(
    "deletePending"
  );


  if (deleteButton) {

    deleteButton.onclick =
    async () => {

      deleteButton.disabled =
      true;


      try {

        const response =
        await chrome.runtime.sendMessage({

          type:
          "deleteDownload",

          downloadId:
          pending.downloadId
        });


        if (
          !response?.ok
        ) {

          throw new Error(
            response?.error ||
            "Could not delete the file."
          );
        }


        panel.classList.add(
          "hidden"
        );


        refresh();


      } catch (error) {

        alert(
          `SafeBox: ${error.message}`
        );

      } finally {

        deleteButton.disabled =
        false;
      }
    };
  }
}


/* =========================================================
 R ender *report
 ========================================================= */

function renderReport(
  item
) {

  if (
    !item?.report
  ) {
    return;
  }


  const report =
  item.report;


  const panel =
  document.getElementById(
    "report"
  );


  if (!panel) {
    return;
  }


  panel.classList.remove(
    "hidden"
  );


  setText(
    "filename",
    item.filename ||
    report.file?.name ||
    "Unknown file"
  );


  setText(
    "filemeta",
    `${bytes(report.file?.size)} • ${
      report.file?.mime_type ||
      "type unknown"
    }`
  );


  const risk =
  report.assessment?.risk ||
  "UNKNOWN";


  const badge =
  document.getElementById(
    "riskBadge"
  );


  if (badge) {

    badge.textContent =
    risk;

    badge.className =
    `risk ${riskClass(risk)}`;
  }


  const clamav =
  report.static_analysis?.clamav;


  setText(
    "clamav",
    clamav?.detected
    ? "THREAT"
    : (
      clamav?.status ||
      "ERROR"
    ).toUpperCase()
  );


  const yaraMatches =
  report.static_analysis?.yara?.matches ||
  [];


  setText(
    "yara",
    yaraMatches.length
    ? `${yaraMatches.length} MATCH`
    : "NO MATCH"
  );


  setText(
    "hash",
    shortHash(
      report.file?.sha256
    )
  );


  setText(
    "action",
    (
      item.action ||
      "scanned"
    ).toUpperCase()
  );


  setText(
    "reason",
    report.assessment?.reason ||
    "No assessment available"
  );


  setText(
    "score",
    `${report.assessment?.score ?? 0}/100`
  );
}


/* =========================================================
 H istory*
 ========================================================= */

function renderHistory(
  recent
) {

  const panel =
  document.getElementById(
    "historyPanel"
  );

  const host =
  document.getElementById(
    "history"
  );


  if (
    !panel ||
    !host
  ) {
    return;
  }


  host.replaceChildren();


  if (
    !Array.isArray(recent) ||
    recent.length === 0
  ) {

    panel.classList.add(
      "hidden"
    );

    return;
  }


  panel.classList.remove(
    "hidden"
  );


  setText(
    "historyCount",
    recent.length
  );


  recent
  .slice(0, 8)
  .forEach(
    (item) => {

      const row =
      document.createElement(
        "div"
      );

      row.className =
      "history-row";


        const name =
        document.createElement(
          "span"
        );

        name.textContent =
        item.filename ||
        "file";


        const risk =
        document.createElement(
          "b"
        );

        risk.textContent =
        `${item.risk || "UNKNOWN"} • ${
          item.action || "scanned"
        }`;


        row.appendChild(
          name
        );

        row.appendChild(
          risk
        );


        host.appendChild(
          row
        );
    }
  );
}


/* =========================================================
 O pen de*dicated scanner page
 ========================================================= */

const chooseFile =
document.getElementById(
  "chooseFile"
);


if (chooseFile) {

  chooseFile.addEventListener(
    "click",
    async () => {

      try {

        await chrome.tabs.create({

          url:
          chrome.runtime.getURL(
            "scanner.html"
          )
        });

      } catch (error) {

        console.error(
          "SafeBox could not open scanner:",
          error
        );

        alert(
          `Could not open SafeBox scanner: ${
            error.message
          }`
        );
      }
    }
  );
}


/* =========================================================
 R efresh* state
 ========================================================= */

function refresh() {

  chrome.runtime.sendMessage(
    {
      type:
      "getState"
    },

    (data) => {

      if (
        chrome.runtime.lastError
      ) {

        console.error(
          chrome.runtime.lastError.message
        );

        return;
      }


      renderPending(
        data?.browserBlocked ||
        null
      );


      if (
        data?.lastReport
      ) {

        renderReport(
          data.lastReport
        );
      }


      renderHistory(
        data?.recent ||
        []
      );
    }
  );
}


/* =========================================================
 I nitial* load
 ========================================================= */

refresh();
