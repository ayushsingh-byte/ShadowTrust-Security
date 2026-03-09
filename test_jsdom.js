const jsdom = require("jsdom");
const { JSDOM } = jsdom;
JSDOM.fromURL("http://localhost:5500/geo.html", { runScripts: "dangerously", resources: "usable" }).then(dom => {
  setTimeout(() => {
    console.log("JSDOM finished.");
  }, 2000);
}).catch(err => console.log(err));
