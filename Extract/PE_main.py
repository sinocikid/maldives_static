import pefile
import array
import math
import pickle
import sys
import pandas as pd
import json
import os


def get_entropy(data):
    if len(data) == 0:
        return 0.0
    occurences = array.array('L', [0] * 256)
    for x in data:
        occurences[x if isinstance(x, int) else ord(x)] += 1

    entropy = 0
    for x in occurences:
        if x:
            p_x = float(x) / len(data)
            entropy -= p_x * math.log(p_x, 2)
    return entropy


def get_resources(pe):
    resources = []
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        try:
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if hasattr(resource_type, 'directory'):
                    for resource_id in resource_type.directory.entries:
                        if hasattr(resource_id, 'directory'):
                            for resource_lang in resource_id.directory.entries:
                                data = pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)
                                size = resource_lang.data.struct.Size
                                entropy = get_entropy(data)
                                resources.append([entropy, size])
        except Exception:
            return resources
    return resources


def get_version_info(pe):
    res = {}
    for fileinfo in pe.FileInfo:
        if fileinfo.Key == 'StringFileInfo':
            for st in fileinfo.StringTable:
                for entry in st.entries.items():
                    res[entry[0]] = entry[1]
        if fileinfo.Key == 'VarFileInfo':
            for var in fileinfo.Var:
                res[list(var.entry.items())[0][0]] = list(var.entry.items())[0][1]
    if hasattr(pe, 'VS_FIXEDFILEINFO'):
        res['flags'] = pe.VS_FIXEDFILEINFO.FileFlags
        res['os'] = pe.VS_FIXEDFILEINFO.FileOS
        res['type'] = pe.VS_FIXEDFILEINFO.FileType
        res['file_version'] = pe.VS_FIXEDFILEINFO.FileVersionLS
        res['product_version'] = pe.VS_FIXEDFILEINFO.ProductVersionLS
        res['signature'] = pe.VS_FIXEDFILEINFO.Signature
        res['struct_version'] = pe.VS_FIXEDFILEINFO.StrucVersion
    return res


def extract_infos(fpath):
    res = {}
    try:
        pe = pefile.PE(fpath)
    except pefile.PEFormatError:
        print("[!] Invalid PE file format.")
        sys.exit(1)

    try:
        res['Machine'] = pe.FILE_HEADER.Machine
        res['SizeOfOptionalHeader'] = pe.FILE_HEADER.SizeOfOptionalHeader
        res['Characteristics'] = pe.FILE_HEADER.Characteristics
        res['MajorLinkerVersion'] = pe.OPTIONAL_HEADER.MajorLinkerVersion
        res['MinorLinkerVersion'] = pe.OPTIONAL_HEADER.MinorLinkerVersion
        res['SizeOfCode'] = pe.OPTIONAL_HEADER.SizeOfCode
        res['SizeOfInitializedData'] = pe.OPTIONAL_HEADER.SizeOfInitializedData
        res['SizeOfUninitializedData'] = pe.OPTIONAL_HEADER.SizeOfUninitializedData
        res['AddressOfEntryPoint'] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        res['BaseOfCode'] = pe.OPTIONAL_HEADER.BaseOfCode
        res['BaseOfData'] = getattr(pe.OPTIONAL_HEADER, 'BaseOfData', 0)
        res['ImageBase'] = pe.OPTIONAL_HEADER.ImageBase
        res['SectionAlignment'] = pe.OPTIONAL_HEADER.SectionAlignment
        res['FileAlignment'] = pe.OPTIONAL_HEADER.FileAlignment
        res['MajorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
        res['MinorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MinorOperatingSystemVersion
        res['MajorImageVersion'] = pe.OPTIONAL_HEADER.MajorImageVersion
        res['MinorImageVersion'] = pe.OPTIONAL_HEADER.MinorImageVersion
        res['MajorSubsystemVersion'] = pe.OPTIONAL_HEADER.MajorSubsystemVersion
        res['MinorSubsystemVersion'] = pe.OPTIONAL_HEADER.MinorSubsystemVersion
        res['SizeOfImage'] = pe.OPTIONAL_HEADER.SizeOfImage
        res['SizeOfHeaders'] = pe.OPTIONAL_HEADER.SizeOfHeaders
        res['CheckSum'] = pe.OPTIONAL_HEADER.CheckSum
        res['Subsystem'] = pe.OPTIONAL_HEADER.Subsystem
        res['DllCharacteristics'] = pe.OPTIONAL_HEADER.DllCharacteristics
        res['SizeOfStackReserve'] = pe.OPTIONAL_HEADER.SizeOfStackReserve
        res['SizeOfStackCommit'] = pe.OPTIONAL_HEADER.SizeOfStackCommit
        res['SizeOfHeapReserve'] = pe.OPTIONAL_HEADER.SizeOfHeapReserve
        res['SizeOfHeapCommit'] = pe.OPTIONAL_HEADER.SizeOfHeapCommit
        res['LoaderFlags'] = pe.OPTIONAL_HEADER.LoaderFlags
        res['NumberOfRvaAndSizes'] = pe.OPTIONAL_HEADER.NumberOfRvaAndSizes

        res['SectionsNb'] = len(pe.sections)
        entropy = [s.get_entropy() for s in pe.sections]
        raw_sizes = [s.SizeOfRawData for s in pe.sections]
        virtual_sizes = [s.Misc_VirtualSize for s in pe.sections]

        res['SectionsMeanEntropy'] = sum(entropy) / len(entropy)
        res['SectionsMinEntropy'] = min(entropy)
        res['SectionsMaxEntropy'] = max(entropy)
        res['SectionsMeanRawsize'] = sum(raw_sizes) / len(raw_sizes)
        res['SectionsMinRawsize'] = min(raw_sizes)
        res['SectionMaxRawsize'] = max(raw_sizes)
        res['SectionsMeanVirtualsize'] = sum(virtual_sizes) / len(virtual_sizes)
        res['SectionsMinVirtualsize'] = min(virtual_sizes)
        res['SectionMaxVirtualsize'] = max(virtual_sizes)

        try:
            res['ImportsNbDLL'] = len(pe.DIRECTORY_ENTRY_IMPORT)
            imports = sum([x.imports for x in pe.DIRECTORY_ENTRY_IMPORT], [])
            res['ImportsNb'] = len(imports)
        except AttributeError:
            res['ImportsNbDLL'] = 0
            res['ImportsNb'] = 0
        res['ImportsNbOrdinal'] = 0

        try:
            res['ExportNb'] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
        except AttributeError:
            res['ExportNb'] = 0

        resources = get_resources(pe)
        res['ResourcesNb'] = len(resources)
        if resources:
            entropy = [r[0] for r in resources]
            sizes = [r[1] for r in resources]
            res['ResourcesMeanEntropy'] = sum(entropy) / len(entropy)
            res['ResourcesMinEntropy'] = min(entropy)
            res['ResourcesMaxEntropy'] = max(entropy)
            res['ResourcesMeanSize'] = sum(sizes) / len(sizes)
            res['ResourcesMinSize'] = min(sizes)
            res['ResourcesMaxSize'] = max(sizes)
        else:
            for k in ['ResourcesMeanEntropy', 'ResourcesMinEntropy', 'ResourcesMaxEntropy',
                      'ResourcesMeanSize', 'ResourcesMinSize', 'ResourcesMaxSize']:
                res[k] = 0

        try:
            res['LoadConfigurationSize'] = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.Size
        except AttributeError:
            res['LoadConfigurationSize'] = 0

        try:
            version_infos = get_version_info(pe)
            res['VersionInformationSize'] = len(version_infos)
        except AttributeError:
            res['VersionInformationSize'] = 0

    except Exception as e:
        print(f"[!] Feature extraction failed: {e}")
        sys.exit(1)

    return res


if __name__ == '__main__':
    if len(sys.argv) < 2 or not os.path.isfile(sys.argv[1]):
        print("Usage: python PE_main.py <path_to_pe_file>")
        sys.exit(1)

    with open('Generator/my_model.pkl', 'rb') as f:
        model = pickle.load(f)

    data = extract_infos(sys.argv[1])
    new_data = pd.DataFrame([data])

    try:
        probability = model.predict_proba(new_data)[0][1]  # Probability that it's legitimate
        prediction = 'legitimate' if probability >= 0.5 else 'malicious'
    except Exception as e:
        print(f"[!] Prediction failed: {e}")
        sys.exit(1)

    print(f"\nThe file is {prediction} (probability: {probability:.3f})")

    with open('Generator/model_accuracy.txt', 'r') as f:
        accuracy = float(f.read().strip())
        print(f"Model accuracy: {accuracy:.3f}")

    output = {
        'file': sys.argv[1],
        'result': prediction,
        'probability': round(probability, 3),
        'accuracy': round(accuracy, 3),
        'features': data
    }

    with open('scan_result.json', 'w') as out:
        json.dump(output, out, indent=2)
        print("\nScan result saved to scan_result.json")
