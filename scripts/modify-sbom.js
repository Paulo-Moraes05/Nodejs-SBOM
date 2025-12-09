import fs from "fs";

// input and output paths
const sbomPath = "merged-cyclonedx-sbom.json";
const outPath = "sbom-custom.json";

// read the JSON file
const sbom = JSON.parse(fs.readFileSync(sbomPath, "utf8"));

function pickComponentTaxonomy(comp) {
  const val = (comp || "").toLowerCase();
  
  if (/\.(tgz|tar|zip|arc|jar|war)$/i.test(val)) return "bsi:component:archive";
  if (/\.(exe|apk|app|scr|bin|dll)$/i.test(val)) return "bsi:component:executable";
  if (/\.(csv|json|ini|yml|yaml|xml|html|css|js|ts|py|rb|php|go|rs|java|txt|md)$/i.test(val)) return "bsi:component:structured";

  // return bsi:component:structured if component is not one of the types
  return "bsi:component:structured";
}

function getFilename(comp) {
  // if comp.properties is an array, use it, otherwise use an empty array
  const props = Array.isArray(comp.properties) ? comp.properties : [];
  const filenameProp =
    props.find(
      (p) =>
        p.name.toLowerCase().includes("srcfile") ||
        p.name.toLowerCase().includes("cdx:bom:componentsrcfiles")
    ) || null;
  
  const resolvedUrl =
    props.find(
      (p) => p.name.toLowerCase().includes("resolvedurl")
    ) || null;

  const syftLocation =
    props.find(
      (p) => p.name.startsWith("syft:location")
    ) || null;

  // strip filename and return url value if resolved url and srcFile are present
  if (resolvedUrl?.value && filenameProp?.value) {
    const stripped_filename = filenameProp.value.split("/").pop();
    filenameProp.value = stripped_filename;
    return resolvedUrl.value;
  }

  // return url value if only resolved url exists
  if (resolvedUrl?.value) return resolvedUrl.value;

  // if property exists, return filename without path
  if (filenameProp?.value) {
    const stripped_filename = filenameProp.value.split("/").pop();
    filenameProp.value = stripped_filename;
    return filenameProp.value;
  }

  // return full path for syft
  if (syftLocation?.value) return syftLocation.value;

  // if component is a file, return the file name
  if (comp.type === "file") {
    // return only filename without the path
    const stripped_filename = comp.name.split("/").pop();
    comp.name = stripped_filename;
    return stripped_filename || "";
  }

  return comp.name || "";
}

function setTaxonomy(comp, taxonomy) {
  comp.properties = Array.isArray(comp.properties) ? comp.properties : [];
  comp.properties = comp.properties.filter(
    (p) =>
      p.name !== "bsi:component:structured" &&
      p.name !== "bsi:component:archive" &&
      p.name !== "bsi:component:executable"
  );
  comp.properties.push({ name: taxonomy, value: "true" });
}
  
function ensureFileProperty(comp) {
  if (!comp) return;

  const filenameLike = getFilename(comp);
  const taxonomy = pickComponentTaxonomy(filenameLike);

  // set taxonomy for all components
  setTaxonomy(comp, taxonomy);

  // set bsi:component:filename only for components with type equal to file
  if (comp.type === "file") {
    comp.properties = Array.isArray(comp.properties) ? comp.properties : [];
    if (!comp.properties.some((p) => p.name === "bsi:component:filename")) {
      comp.properties.push({ name: "bsi:component:filename", value: comp.name || "" });
    }
  } 
}

// loop through the components in the JSON file
for (const comp of sbom.components || []) {
  ensureFileProperty(comp);
}

fs.writeFileSync(outPath, JSON.stringify(sbom, null, 2));
console.log("Custom SBOM written to sbom-custom.json");
