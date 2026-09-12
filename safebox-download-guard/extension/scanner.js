/* =========================================================
   SafeBox Dedicated Scanner Page
========================================================= */


/* =========================================================
   Helpers
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


function safeJson(
  value
) {

  try {

    return JSON.stringify(
      value,
      null,
      2
    );

  } catch (error) {

    return (
      `Unable to render evidence: ${error.message}`
    );
  }
}


/* =========================================================
   Base64
========================================================= */

function toB64(
  buffer
) {

  const bytesArray =
    new Uint8Array(
      buffer
    );


  let result = "";

  const chunkSize =
    0x8000;


  for (
    let index = 0;
    index < bytesArray.length;
    index += chunkSize
  ) {

    const chunk =
      bytesArray.subarray(
        index,
        Math.min(
          index + chunkSize,
          bytesArray.length
        )
      );


    result +=
      String.fromCharCode(
        ...chunk
      );
  }


  return btoa(
    result
  );
}


/* =========================================================
   Evidence
========================================================= */

function renderEvidence(
  report
) {

  const evidence =
    document.getElementById(
      "evidence"
    );


  if (!evidence) {
    return;
  }


  evidence.replaceChildren();


  const findings =
    report.assessment?.evidence ||
    [];


  if (
    !findings.length
  ) {

    const row =
      document.createElement(
        "div"
      );

    row.className =
      "evidence-row";

    row.textContent =
      "No additional evidence.";

    evidence.appendChild(
      row
    );

    return;
  }


  findings.forEach(
    (finding) => {

      const row =
        document.createElement(
          "div"
        );

      row.className =
        "evidence-row";


      const source =
        document.createElement(
          "b"
        );

      source.textContent =
        finding.source ||
        "SCAN";


      const message =
        document.createElement(
          "span"
        );

      message.textContent =
        finding.message ||
        "";


      row.appendChild(
        source
      );

      row.appendChild(
        message
      );


      evidence.appendChild(
        row
      );
    }
  );
}


/* =========================================================
   Detailed Evidence
========================================================= */

function renderDetails(
  item
) {

  const details =
    document.getElementById(
      "details"
    );


  if (!details) {
    return;
  }


  const report =
    item.report;


  const detailObject = {

    file:
      report.file,

    browser:
      report.browser,

    static_analysis:
      report.static_analysis,

    dynamic_analysis:
      report.dynamic_analysis,

    quarantine:
      report.quarantine,

    assessment:
      report.assessment,

    action:
      item.action
  };


  details.textContent =
    safeJson(
      detailObject
    );
}


/* =========================================================
   Render Report
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


  const result =
    document.getElementById(
      "result"
    );


  if (result) {

    result.classList.remove(
      "hidden"
    );
  }


  /* -------------------------------------------------------
     File
  ------------------------------------------------------- */

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


  /* -------------------------------------------------------
     Risk
  ------------------------------------------------------- */

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


  /* -------------------------------------------------------
     ClamAV
  ------------------------------------------------------- */

  const clamav =
    report.static_analysis?.clamav;


  if (
    clamav?.detected
  ) {

    setText(
      "clamav",
      "THREAT"
    );

  } else {

    setText(
      "clamav",
      (
        clamav?.status ||
        "ERROR"
      ).toUpperCase()
    );
  }


  /* -------------------------------------------------------
     YARA
  ------------------------------------------------------- */

  const yaraMatches =
    report.static_analysis?.yara?.matches ||
    [];


  setText(
    "yara",
    yaraMatches.length
      ? `${yaraMatches.length} MATCH`
      : "NO MATCH"
  );


  /* -------------------------------------------------------
     Hash
  ------------------------------------------------------- */

  setText(
    "hash",
    shortHash(
      report.file?.sha256
    )
  );


  /* -------------------------------------------------------
     Score
  ------------------------------------------------------- */

  setText(
    "score",
    `${report.assessment?.score ?? 0}/100`
  );


  /* -------------------------------------------------------
     Reason
  ------------------------------------------------------- */

  setText(
    "reason",
    report.assessment?.reason ||
      "No assessment available"
  );


  renderEvidence(
    report
  );

  renderDetails(
    item
  );
}


/* =========================================================
   Status
========================================================= */

function showStatus(
  message
) {

  const panel =
    document.getElementById(
      "statusPanel"
    );


  if (!panel) {
    return;
  }


  panel.classList.remove(
    "hidden"
  );


  setText(
    "statusText",
    message
  );
}


/* =========================================================
   File selection
========================================================= */

const chooseButton =
  document.getElementById(
    "chooseFile"
  );


const fileInput =
  document.getElementById(
    "fileInput"
  );


const selectedFile =
  document.getElementById(
    "selectedFile"
  );


const scanButton =
  document.getElementById(
    "scanFile"
  );


if (
  chooseButton &&
  fileInput
) {

  chooseButton.addEventListener(
    "click",
    () => {

      fileInput.click();
    }
  );
}


/* =========================================================
   Selection change
========================================================= */

if (
  fileInput &&
  selectedFile &&
  scanButton
) {

  fileInput.addEventListener(
    "change",
    (event) => {

      const file =
        event.target.files?.[0];


      if (!file) {

        selectedFile.classList.add(
          "hidden"
        );

        scanButton.disabled =
          true;

        return;
      }


      /*
       * Keep the scan deliberately small for the
       * extension page. Browser downloading can handle
       * larger files through the native host.
       */

      if (
        file.size >
        100 * 1024
      ) {

        alert(
          "Maximum manual scan size is 100 KB."
        );


        event.target.value =
          "";


        selectedFile.classList.add(
          "hidden"
        );

        scanButton.disabled =
          true;

        return;
      }


      selectedFile.classList.remove(
        "hidden"
      );


      setText(
        "selectedName",
        file.name
      );


      setText(
        "selectedSize",
        bytes(
          file.size
        )
      );


      scanButton.disabled =
        false;
    }
  );
}


/* =========================================================
   Scan
========================================================= */

if (scanButton) {

  scanButton.addEventListener(
    "click",
    async () => {

      const file =
        fileInput?.files?.[0];


      if (!file) {
        return;
      }


      scanButton.disabled =
        true;


      const originalText =
        scanButton.textContent;


      scanButton.textContent =
        "⏳ Scanning…";


      showStatus(
        "Sending file to local SafeBox engine…"
      );


      try {

        const buffer =
          await file.arrayBuffer();


        const response =
          await chrome.runtime.sendMessage({

            type:
              "scanSelectedFile",

            file: {

              name:
                file.name,

              mimeType:
                file.type ||
                "application/octet-stream",

              size:
                file.size,

              base64:
                toB64(buffer)
            }
          });


        if (
          !response?.ok
        ) {

          throw new Error(
            response?.error ||
            "SafeBox scan failed."
          );
        }


        renderReport(
          response.item
        );


        showStatus(
          "Scan completed locally."
        );


      } catch (error) {

        console.error(
          "SafeBox scanner error:",
          error
        );


        showStatus(
          `Scan failed: ${error.message}`
        );


        alert(
          `SafeBox scan failed:\n${error.message}`
        );


      } finally {

        scanButton.disabled =
          false;

        scanButton.textContent =
          originalText;
      }
    }
  );
}
