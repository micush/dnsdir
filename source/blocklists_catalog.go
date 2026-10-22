package main

// The block lists dnsdir knows by name (Configure ▸ DNS proxy ▸ Resolution ▸ Block Lists).  Only the address of each is
// kept here: every node downloads the lists itself, from the publisher, when they are switched on.  Addresses change now and
// then (OISD moved its lists to another format once), so a list's address can be replaced in its row, and a list that
// cannot be downloaded says why instead of failing quietly.

// BlockCatalogItem is one list on offer.
type BlockCatalogItem struct {
	ID      string `json:"id"`
	Group   string `json:"group"`
	Name    string `json:"name"`
	Desc    string `json:"desc"`
	URL     string `json:"url"`
	Risk    string `json:"risk"`    // how likely it is to block something wanted: low, moderate, high
	Entries int    `json:"entries"` // about how many domains it holds (they change with every build)
}

const (
	hageziBase = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/"
	sbBase     = "https://raw.githubusercontent.com/StevenBlack/hosts/master/"
)

// Groups, in the order they are shown.
const (
	grpHagezi  = "HaGeZi: pick one of these (each includes the ones above it)"
	grpHExtra  = "HaGeZi: extras"
	grpOISD    = "OISD"
	grpStevenB = "StevenBlack"
	grpOther   = "Others"
)

var blockCatalog = []BlockCatalogItem{
	{"hagezi-light", grpHagezi, "HaGeZi Light", "Basic protection: ads, trackers, telemetry, some malware. Should not restrict anything.", hageziBase + "light-onlydomains.txt", "low", 68000},
	{"hagezi-normal", grpHagezi, "HaGeZi Normal", "All-round protection. Mostly will not restrict anything either.", hageziBase + "multi-onlydomains.txt", "low", 158000},
	{"hagezi-pro", grpHagezi, "HaGeZi Pro (suggested)", "Ads, trackers, telemetry, malware, phishing. Balanced: low breakage.", hageziBase + "pro-onlydomains.txt", "low", 206000},
	{"hagezi-proplus", grpHagezi, "HaGeZi Pro++", "Pro, more aggressive. Some legitimate sites and apps may break.", hageziBase + "pro.plus-onlydomains.txt", "moderate", 247000},
	{"hagezi-ultimate", grpHagezi, "HaGeZi Ultimate", "Maximum protection and the most breakage. Use with a way to allow what it blocks.", hageziBase + "ultimate-onlydomains.txt", "high", 283000},

	{"hagezi-tif-mini", grpHExtra, "HaGeZi Threat Intelligence (mini)", "Malware, scam and phishing feeds, the small version. Good beside any tier.", hageziBase + "tif.mini-onlydomains.txt", "low", 170000},
	{"hagezi-tif-medium", grpHExtra, "HaGeZi Threat Intelligence (medium)", "The same feeds, a larger set.", hageziBase + "tif.medium-onlydomains.txt", "low", 379000},
	{"hagezi-tif", grpHExtra, "HaGeZi Threat Intelligence (full)", "Every feed. Very large: needs a few hundred MB of memory on each node.", hageziBase + "tif-onlydomains.txt", "low", 2194000},
	{"hagezi-hoster", grpHExtra, "HaGeZi Badware Hoster", "Hosts that serve badware.", hageziBase + "hoster-onlydomains.txt", "low", 1000},

	{"oisd-small", grpOISD, "OISD Small", "\"Block. Don't break.\" The small set: ads and malware.", "https://small.oisd.nl/domainswild2", "low", 58000},
	{"oisd-big", grpOISD, "OISD Big", "The main set: ads, trackers, malware, phishing.", "https://big.oisd.nl/domainswild2", "low", 234000},
	{"oisd-nsfw", grpOISD, "OISD NSFW", "Adult sites. Use beside OISD Big or another list.", "https://nsfw.oisd.nl/domainswild2", "low", 473000},

	{"stevenblack", grpStevenB, "StevenBlack Unified", "Ads and malware, from several well-known sources.", sbBase + "hosts", "low", 80000},
	{"stevenblack-fakenews", grpStevenB, "StevenBlack: fake news", "Only the fake news extension (add it to Unified).", sbBase + "alternates/fakenews-only/hosts", "low", 0},
	{"stevenblack-gambling", grpStevenB, "StevenBlack: gambling", "Only the gambling extension.", sbBase + "alternates/gambling-only/hosts", "low", 6700},
	{"stevenblack-porn", grpStevenB, "StevenBlack: porn", "Only the porn extension.", sbBase + "alternates/porn-only/hosts", "low", 0},
	{"stevenblack-social", grpStevenB, "StevenBlack: social", "Only the social media extension.", sbBase + "alternates/social-only/hosts", "moderate", 0},

	{"frogeye-firstparty", grpOther, "Frogeye first-party trackers", "Trackers that hide behind a name in the site's own domain (CNAME cloaking), rebuilt daily.", "https://hostfiles.frogeye.fr/firstparty-trackers-hosts.txt", "moderate", 15000},
}

// catalogItem finds a list on offer by its id.
func catalogItem(id string) *BlockCatalogItem {
	for i := range blockCatalog {
		if blockCatalog[i].ID == id {
			return &blockCatalog[i]
		}
	}
	return nil
}
