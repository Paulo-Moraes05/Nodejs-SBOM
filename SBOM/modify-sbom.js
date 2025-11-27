import fs from "fs";

// read the JSON file
const sbom = JSON.parse(fs.readFileSync("sbom.json", "utf8"));

// loop through the components in the JSON file
for (const comp of sbom.components || []) {
  comp.properties = comp.properties || [];

  // find the type of the component
  const srcFile = (comp.properties || []).find(p => p.name.toLowerCase().includes("srcfile") || p.name.toLowerCase().includes("cdx:bom:componentsrcfiles"))

  if (!srcFile) continue;

  const value = srcFile.value.toLowerCase();
  let taxonomy = "";

  // search for a match for the specified RegExp
  if (/\.(tgz|tar|zip|arc|jar|war)$/i.test(value)) {
    taxonomy = "bsi:component:archive";
  } else if (/\.(exe|apk|app|scr|bin)$/i.test(value)) {
    taxonomy = "bsi:component:executable";
  } else if (/\.(csv|json|ini|yml|yaml|xml|html|css|js)$/i.test(value)) {
    taxonomy = "bsi:component:structured";
  } else {
    // default value for unknown component type
    taxonomy = "bsi:component:structured";
  }

  if (!comp.properties.some(p => p.name === taxonomy)) {
    comp.properties.push({
      name: taxonomy,
      value: "true",
    });
  }

  // add filename following BSI's taxonomy
  if (!comp.properties.some(p => p.name === "bsi:component:filename")) {
    srcFile.name = "bsi:component:filename";
    const valueSlice = srcFile.value.slice(srcFile.value.lastIndexOf("/") + 1);
    srcFile.value = valueSlice;
  }

}



fs.writeFileSync("sbom-custom.json", JSON.stringify(sbom, null, 2));
console.log("Custom SBOM written to sbom-custom.json");