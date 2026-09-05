package ociinstance

import "github.com/oracle/oci-go-sdk/v65/common"

// Pin the SDK v65.124.1 public region-code vocabulary. Calling StringToRegion
// on an unknown IMDS value can fall back to environment/config-file region
// metadata or an unbounded SDK metadata client. Admission must do neither.
var metadataAliases = map[string]common.Region{
	"yny": common.RegionAPChuncheon1,
	"hyd": common.RegionAPHyderabad1,
	"mel": common.RegionAPMelbourne1,
	"bom": common.RegionAPMumbai1,
	"kix": common.RegionAPOsaka1,
	"icn": common.RegionAPSeoul1,
	"syd": common.RegionAPSydney1,
	"nrt": common.RegionAPTokyo1,
	"yul": common.RegionCAMontreal1,
	"yyz": common.RegionCAToronto1,
	"ams": common.RegionEUAmsterdam1,
	"fra": common.RegionFRA,
	"zrh": common.RegionEUZurich1,
	"jed": common.RegionMEJeddah1,
	"dxb": common.RegionMEDubai1,
	"gru": common.RegionSASaopaulo1,
	"cwl": common.RegionUKCardiff1,
	"lhr": common.RegionLHR,
	"iad": common.RegionIAD,
	"phx": common.RegionPHX,
	"sjc": common.RegionSJC1,
	"vcp": common.RegionSAVinhedo1,
	"scl": common.RegionSASantiago1,
	"mtz": common.RegionILJerusalem1,
	"mrs": common.RegionEUMarseille1,
	"sin": common.RegionAPSingapore1,
	"auh": common.RegionMEAbudhabi1,
	"lin": common.RegionEUMilan1,
	"arn": common.RegionEUStockholm1,
	"jnb": common.RegionAFJohannesburg1,
	"cdg": common.RegionEUParis1,
	"qro": common.RegionMXQueretaro1,
	"mad": common.RegionEUMadrid1,
	"ord": common.RegionUSChicago1,
	"mty": common.RegionMXMonterrey1,
	"aga": common.RegionUSSaltlake2,
	"bog": common.RegionSABogota1,
	"vap": common.RegionSAValparaiso1,
	"xsp": common.RegionAPSingapore2,
	"ruh": common.RegionMERiyadh1,
	"onm": common.RegionAPDelhi1,
	"hsg": common.RegionAPBatam1,
	"orf": common.RegionEUMadrid3,
	"nrq": common.RegionEUTurin1,
	"jbp": common.RegionAPKulai2,
	"lej": common.RegionAFCasablanca1,
	"lfi": common.RegionUSLangley1,
	"luf": common.RegionUSLuke1,
	"ric": common.RegionUSGovAshburn1,
	"pia": common.RegionUSGovChicago1,
	"tus": common.RegionUSGovPhoenix1,
	"ltn": common.RegionUKGovLondon1,
	"brs": common.RegionUKGovCardiff1,
	"nja": common.RegionAPChiyoda1,
	"ukb": common.RegionAPIbaraki1,
	"mct": common.RegionMEDccMuscat1,
	"ibr": common.RegionMEIbri1,
	"wga": common.RegionAPDccCanberra1,
	"bgy": common.RegionEUDccMilan1,
	"mxp": common.RegionEUDccMilan2,
	"snn": common.RegionEUDccDublin2,
	"dtm": common.RegionEUDccRating2,
	"dus": common.RegionEUDccRating1,
	"ork": common.RegionEUDccDublin1,
	"dac": common.RegionAPDccGazipur1,
	"vll": common.RegionEUMadrid2,
	"str": common.RegionEUFrankfurt2,
	"beg": common.RegionEUJovanovac1,
	"doh": common.RegionMEDccDoha1,
	"vve": common.RegionMEAlrayyan1,
	"ebb": common.RegionUSSomerset1,
	"ebl": common.RegionUSThames1,
	"avz": common.RegionEUDccZurich1,
	"avf": common.RegionEUCrissier1,
	"ahu": common.RegionMEAbudhabi3,
	"rba": common.RegionMEAlain1,
	"rkt": common.RegionMEAbudhabi2,
	"shj": common.RegionMEAbudhabi4,
	"dtz": common.RegionAPSeoul2,
	"dln": common.RegionAPSuwon1,
	"bno": common.RegionAPChuncheon2,
	"yxj": common.RegionUSAshburn2,
	"pgc": common.RegionUSNewark1,
	"jsk": common.RegionEUBudapest1,
	"hnw": common.RegionSARiodejaneiro1,
}

func matchesMetadataRegion(observed, expected string) bool {
	if observed == expected {
		return true
	}
	canonical, ok := metadataAliases[observed]
	return ok && string(canonical) == expected
}

// The signed destination vocabulary is limited to the SDK-pinned commercial
// realm; other OCI realms require distinct endpoint contracts.
func validHomeRegion(region string) bool {
	for _, known := range metadataAliases {
		if string(known) == region {
			realm, err := known.RealmID()
			return err == nil && realm == "oc1"
		}
	}
	return false
}
