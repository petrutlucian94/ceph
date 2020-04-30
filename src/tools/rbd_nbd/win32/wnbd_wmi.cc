/*
 * Copyright (c) 2019 SUSE LLC
 *
 * Licensed under LGPL-2.1 (see LICENSE)
 */

#include "wnbd_wmi.h"

#include "include/win32/win32_errno.h"

IWbemLocator* pWbemLoc;
// NOTE: this simple abstraction only exposes the "root/cimv2"
// WMI namespace.
IWbemServices* pWbemSvc;

bool ReleaseWMI()
{
  if (pWbemSvc != NULL) {
    pWbemSvc->Release();
    pWbemSvc = NULL;
  }
  if (pWbemLoc != NULL) {
    pWbemLoc->Release();
    pWbemLoc = NULL;
  }

  CoUninitialize();
  return true;
}

bool InitWMI()
{
  HRESULT hr;
  hr = CoInitializeEx(0, COINIT_MULTITHREADED);
  if (FAILED(hr))
    return false;

  hr = CoInitializeSecurity(
    NULL, -1, NULL, NULL,
    RPC_C_AUTHN_LEVEL_DEFAULT,
    RPC_C_IMP_LEVEL_IMPERSONATE,
    NULL,
    EOAC_NONE,
    NULL);
  if (FAILED(hr))
    return false;

  HRESULT hres = CoCreateInstance(
    CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
    IID_IWbemLocator, (LPVOID*)&pWbemLoc);
  if (FAILED(hres))
  {
    ReleaseWMI();
    return false;
  }
  BSTR bstr_wmi_ns = SysAllocString(L"ROOT\\CIMV2");
  hres = pWbemLoc->ConnectServer(
    bstr_wmi_ns, NULL, NULL, NULL,
    WBEM_FLAG_CONNECT_USE_MAX_WAIT, NULL, NULL, &pWbemSvc);
  SysFreeString(bstr_wmi_ns);
  if (FAILED(hres))
  {
    ReleaseWMI();
    return false;
  }

  hres = CoSetProxyBlanket(
    pWbemSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
    RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
  if (FAILED(hres))
  {
    ReleaseWMI();
    return false;
  }

  return true;
}

std::wstring GetProperty(IWbemClassObject* pclsObj,
                         const std::wstring& property)
{
  std::wstring retVal(L"");
  VARIANT vtProp;
  VariantInit(&vtProp);
  HRESULT hr;
  hr = pclsObj->Get(property.c_str(), 0, &vtProp, 0, 0);
  if (!FAILED(hr))
  {
    VARIANT vtBstrProp;
    VariantInit(&vtBstrProp);
    hr = VariantChangeType(&vtBstrProp, &vtProp, 0, VT_BSTR);
    if (!FAILED(hr))
    {
      retVal = vtBstrProp.bstrVal;
    }
    VariantClear(&vtBstrProp);
  }
  VariantClear(&vtProp);

  return retVal;
}

UINT32 GetPropertyInt(IWbemClassObject* pclsObj, const std::wstring& property)
{
  UINT32 retVal = 0;
  VARIANT vtProp;
  VariantInit(&vtProp);
  HRESULT hr;
  hr = pclsObj->Get(property.c_str(), 0, &vtProp, 0, 0);
  if (!FAILED(hr))
  {
    VARIANT vtBstrProp;
    VariantInit(&vtBstrProp);
    hr = VariantChangeType(&vtBstrProp, &vtProp, 0, VT_UINT);
    if (!FAILED(hr))
    {
      retVal = vtBstrProp.intVal;
    }
    VariantClear(&vtBstrProp);
  }
  VariantClear(&vtProp);

  return retVal;
}

bool GetDiskDrives(BSTR Query, std::vector<DiskInfo>& disks)
{
  bool bRet = false;

  HRESULT hres;
  IEnumWbemClassObject* pEnumerator = NULL;
  IWbemClassObject* pclsObj = NULL;

  if (pWbemSvc)
  {
    BSTR bstr_wql = SysAllocString(L"WQL");
    hres = pWbemSvc->ExecQuery(
      bstr_wql, Query,
      WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
      NULL, &pEnumerator);
    SysFreeString(bstr_wql);
    if (!FAILED(hres))
    {
      ULONG uReturn = 0;
      while (pEnumerator)
      {
        pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
        if (uReturn == 0)
          break;
        DiskInfo d;
        d.deviceId = GetProperty(pclsObj, L"DeviceID");
        d.freeSpace = GetProperty(pclsObj, L"FreeSpace");
        d.Index = GetPropertyInt(pclsObj, L"Index");
        disks.push_back(d);
        bRet = true;
      }
      if (pclsObj != NULL)
        pclsObj->Release();
      if (pEnumerator != NULL)
        pEnumerator->Release();
    }
  }

  return bRet;
}

bool GetDiskDrivesBySerialNumber(std::wstring serialNumber,
                                std::vector<DiskInfo>& disks) {
  std::wstring query = L"SELECT * FROM Win32_DiskDrive WHERE SerialNumber = '";
  query.append(serialNumber);
  query.append(L"'");
  BSTR bstrQuery = SysAllocString(query.c_str());

  bool bRet = GetDiskDrives(bstrQuery, disks);

  SysFreeString(bstrQuery);
  return bRet;
}

int GetDiskNumberBySerialNumber(std::wstring serialNumber) {
  std::vector<DiskInfo> d;
  GetDiskDrivesBySerialNumber(serialNumber, d);
  if (d.size() > 1) {
    return -ENOTUNIQ;
  }
  if (d.size() < 1) {
    return -ENOENT;
  }

  return d[0].Index;
}
