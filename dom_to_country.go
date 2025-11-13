package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	//"github.com/emirpasic/gods/maps/hashmap"
	"github.com/likexian/whois"
	"github.com/likexian/whois-parser"
)
var timestamp = time.Now().Format("2006-01-02_15-04-05")
var tldToCountry = map[string]string{
	"af": "Afghanistan",
	"ax": "Åland",
	"al": "Albania",
	"dz": "Algeria",
	"as": "American Samoa",
	"ad": "Andorra",
	"ao": "Angola",
	"ai": "Anguilla",
	"aq": "Antarctica",
	"ag": "Antigua and Barbuda",
	"ar": "Argentina",
	"am": "Armenia",
	"aw": "Aruba",
	"ac": "Ascension Island",
	"au": "Australia",
	"at": "Austria",
	"az": "Azerbaijan",
	"bs": "Bahamas",
	"bh": "Bahrain",
	"bd": "Bangladesh",
	"bb": "Barbados",
	"eus": "Basque Country",
	"by": "Belarus",
	"be": "Belgium",
	"bz": "Belize",
	"bj": "Benin",
	"bm": "Bermuda",
	"bt": "Bhutan",
	"bo": "Bolivia",
	"bq": "Bonaire",
	"an": "Netherlands Antilles",
	"ba": "Bosnia and Herzegovina",
	"bw": "Botswana",
	"bv": "Bouvet Island",
	"br": "Brazil",
	"io": "British Indian Ocean Territory",
	"vg": "British Virgin Islands",
	"bn": "Brunei",
	"bg": "Bulgaria",
	"bf": "Burkina Faso",
	"mm": "Myanmar",
	"bi": "Burundi",
	"kh": "Cambodia",
	"cm": "Cameroon",
	"ca": "Canada",
	"cv": "Cape Verde",
	"cat": "Catalonia",
	"ky": "Cayman Islands",
	"cf": "Central African Republic",
	"td": "Chad",
	"cl": "Chile",
	"cn": "China, People’s Republic of",
	"cx": "Christmas Island",
	"cc": "Cocos (Keeling) Islands",
	"co": "Colombia",
	"km": "Comoros",
	"cd": "Congo, Democratic Republic of the",
	"cg": "Congo, Republic of the",
	"ck": "Cook Islands",
	"cr": "Costa Rica",
	"ci": "Côte d’Ivoire (Ivory Coast)",
	"hr": "Croatia",
	"cu": "Cuba",
	"cw": "Curaçao",
	"cy": "Cyprus",
	"cz": "Czechia",
	"dk": "Denmark",
	"dj": "Djibouti",
	"dm": "Dominica",
	"do": "Dominican Republic",
	"tl": "Timor-Leste",
	"tp": "Timor-Leste",
	"ec": "Ecuador",
	"eg": "Egypt",
	"sv": "El Salvador",
	"gq": "Equatorial Guinea",
	"er": "Eritrea",
	"ee": "Estonia",
	"et": "Ethiopia",
	"eu": "European Union",
	"fk": "Falkland Islands",
	"fo": "Faroe Islands",
	"fm": "Federated States of Micronesia",
	"fj": "Fiji",
	"fi": "Finland",
	"fr": "France",
	"gf": "French Guiana",
	"pf": "French Polynesia",
	"tf": "French Southern and Antarctic Lands",
	"ga": "Gabon",
	"gal": "Galicia",
	"gm": "Gambia",
	"ps": "Palestine",
	"ge": "Georgia",
	"de": "Germany",
	"gh": "Ghana",
	"gi": "Gibraltar",
	"gr": "Greece",
	"gl": "Greenland",
	"gd": "Grenada",
	"gp": "Guadeloupe",
	"gu": "Guam",
	"gt": "Guatemala",
	"gg": "Guernsey",
	"gn": "Guinea",
	"gw": "Guinea-Bissau",
	"gy": "Guyana",
	"ht": "Haiti",
	"hm": "Heard Island and McDonald Islands",
	"hn": "Honduras",
	"hk": "Hong Kong",
	"hu": "Hungary",
	"is": "Iceland",
	"in": "India",
	"id": "Indonesia",
	"ir": "Iran",
	"iq": "Iraq",
	"ie": "Ireland",
	"im": "Isle of Man",
	"il": "Israel",
	"it": "Italy",
	"jm": "Jamaica",
	"jp": "Japan",
	"je": "Jersey",
	"jo": "Jordan",
	"kz": "Kazakhstan",
	"ke": "Kenya",
	"ki": "Kiribati",
	"kw": "Kuwait",
	"kg": "Kyrgyzstan",
	"la": "Laos",
	"lv": "Latvia",
	"lb": "Lebanon",
	"ls": "Lesotho",
	"lr": "Liberia",
	"ly": "Libya",
	"li": "Liechtenstein",
	"lt": "Lithuania",
	"lu": "Luxembourg",
	"mo": "Macau",
	"mk": "North Macedonia",
	"mg": "Madagascar",
	"mw": "Malawi",
	"my": "Malaysia",
	"mv": "Maldives",
	"ml": "Mali",
	"mt": "Malta",
	"mh": "Marshall Islands",
	"mq": "Martinique",
	"mr": "Mauritania",
	"mu": "Mauritius",
	"yt": "Mayotte",
	"mx": "Mexico",
	"md": "Moldova",
	"mc": "Monaco",
	"mn": "Mongolia",
	"me": "Montenegro",
	"ms": "Montserrat",
	"ma": "Morocco",
	"mz": "Mozambique",
	"na": "Namibia",
	"nr": "Nauru",
	"np": "Nepal",
	"nl": "Netherlands",
	"nc": "New Caledonia",
	"nz": "New Zealand",
	"ni": "Nicaragua",
	"ne": "Niger",
	"ng": "Nigeria",
	"nu": "Niue",
	"nf": "Norfolk Island",
	"kp": "North Korea",
	"mp": "Northern Mariana Islands",
	"no": "Norway",
	"om": "Oman",
	"pk": "Pakistan",
	"pw": "Palau",
	"pa": "Panama",
	"pg": "Papua New Guinea",
	"py": "Paraguay",
	"pe": "Peru",
	"ph": "Philippines",
	"pn": "Pitcairn Islands",
	"pl": "Poland",
	"pt": "Portugal",
	"pr": "Puerto Rico",
	"qa": "Qatar",
	"ro": "Romania",
	"ru": "Russia",
	"rw": "Rwanda",
	"re": "Réunion Island",
	"sh": "Saint Helena",
	"kn": "Saint Kitts and Nevis",
	"lc": "Saint Lucia",
	"pm": "Saint Pierre and Miquelon",
	"vc": "Saint Vincent and the Grenadines",
	"ws": "Samoa",
	"sm": "San Marino",
	"st": "São Tomé and Príncipe",
	"sa": "Saudi Arabia",
	"sn": "Senegal",
	"rs": "Serbia",
	"sc": "Seychelles",
	"sl": "Sierra Leone",
	"sg": "Singapore",
	"sk": "Slovakia",
	"si": "Slovenia",
	"sb": "Solomon Islands",
	"so": "Somalia",
	"za": "South Africa",
	"gs": "South Georgia and the South Sandwich Islands",
	"kr": "South Korea",
	"ss": "South Sudan",
	"es": "Spain",
	"lk": "Sri Lanka",
	"sd": "Sudan",
	"sr": "Suriname",
	"sj": "Svalbard and Jan Mayen Islands",
	"sz": "Eswatini",
	"se": "Sweden",
	"ch": "Switzerland",
	"sy": "Syria",
	"tw": "Taiwan",
	"tj": "Tajikistan",
	"tz": "Tanzania",
	"th": "Thailand",
	"tg": "Togo",
	"tk": "Tokelau",
	"to": "Tonga",
	"tt": "Trinidad & Tobago",
	"tn": "Tunisia",
	"tr": "Turkey",
	"tm": "Turkmenistan",
	"tc": "Turks and Caicos Islands",
	"tv": "Tuvalu",
	"ug": "Uganda",
	"ua": "Ukraine",
	"ae": "United Arab Emirates",
	"uk": "United Kingdom",
	"us": "United States",
	"vi": "United States Virgin Islands",
	"uy": "Uruguay",
	"uz": "Uzbekistan",
	"vu": "Vanuatu",
	"va": "Vatican City",
	"ve": "Venezuela",
	"vn": "Vietnam",
	"wf": "Wallis and Futuna",
	"eh": "Western Sahara",
	"ye": "Yemen",
	"zm": "Zambia",
	"zw": "Zimbabwe",
}
type WhoisInfo struct {
	OrgName  string
	City     string
	State    string
	Country  string
	Address  string
	NetRange string
	NetName  string
}

func ParseWhois(raw string) WhoisInfo {
	lines := strings.Split(raw, "\n")
	info := WhoisInfo{}

	reOrgName := regexp.MustCompile(`(?i)^OrgName:\s*(.+)`)
	reCity := regexp.MustCompile(`(?i)^City:\s*(.+)`)
	reState := regexp.MustCompile(`(?i)^StateProv:\s*(.+)`)
	reCountry := regexp.MustCompile(`(?i)^Country:\s*(.+)`)
	reAddress := regexp.MustCompile(`(?i)^Address:\s*(.+)`)
	reNetRange := regexp.MustCompile(`(?i)^NetRange:\s*(.+)`)
	reNetName := regexp.MustCompile(`(?i)^NetName:\s*(.+)`)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if info.OrgName == "" && reOrgName.MatchString(line) {
			info.OrgName = strings.TrimSpace(reOrgName.FindStringSubmatch(line)[1])
		}
		if info.City == "" && reCity.MatchString(line) {
			info.City = strings.TrimSpace(reCity.FindStringSubmatch(line)[1])
		}
		if info.State == "" && reState.MatchString(line) {
			info.State = strings.TrimSpace(reState.FindStringSubmatch(line)[1])
		}
		if info.Country == "" && reCountry.MatchString(line) {
			info.Country = strings.TrimSpace(reCountry.FindStringSubmatch(line)[1])
		}
		if info.Address == "" && reAddress.MatchString(line) {
			info.Address = strings.TrimSpace(reAddress.FindStringSubmatch(line)[1])
		}
		if info.NetRange == "" && reNetRange.MatchString(line) {
			info.NetRange = strings.TrimSpace(reNetRange.FindStringSubmatch(line)[1])
		}
		if info.NetName == "" && reNetName.MatchString(line) {
			info.NetName = strings.TrimSpace(reNetName.FindStringSubmatch(line)[1])
		}
	}

	return info
}

func get_ip(domain string) string {
	ip_address , err := net.LookupIP(domain);
	if err != nil {
		return "";
	}
	
	return ip_address[0].String();
}


func parse_country(country string) string{
	country = strings.ToLower(country);
	if val, ok := tldToCountry[country]; ok {
		return val;
	}
	if(country==strings.ToLower("EU # Country is really world wide")){
		return "European Union";
	}
	return "Unknown";
}

func whois_info(domain string) string{
	whois_raw,err := whois.Whois(get_ip(domain));
	if err != nil {
		return "error";
	}
	return whois_raw;

}

func parse_whois(whois_raw string){
	result,err := whoisparser.Parse(whois_raw);
	if err != nil {
		fmt.Println("Error parsing WHOIS data:", err);
		return;
	}
	fmt.Println(result);
}

func save_data(country string,email string){
	folder_name := parse_country(country);
	
    file_name := strings.ReplaceAll(folder_name, " ", "_") + "_" + timestamp + ".txt"
	err :=os.MkdirAll(folder_name, os.ModePerm);
	if err != nil {
		fmt.Println("Error creating folder:", err);
		return;
	}
	file_path := fmt.Sprintf("%s/%s",folder_name,file_name);
	f, err := os.OpenFile(file_path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644);
	if err != nil {
		fmt.Println("Error opening/creating file:", err);
		return;
	}
	defer f.Close()
	_, err = f.WriteString(email+"\n");
	if err != nil {
		fmt.Println("Error writing to file:", err);
		return;
	}
}

func get_domain(email string) string{
	if email ==""{
		return "";
	}

	parts := strings.Split(email,"@") ;
	if len(parts) !=2{
		return "";
	} 
	return parts[1];
}

func workers(wg *sync.WaitGroup, ch <- chan string , dom_hash_map *sync.Map, country_hash *sync.Map , mu *sync.Mutex){
	defer wg.Done()
	for email := range ch {
		domain := get_domain(email);
		if domain ==""{
			continue;
		}
		val , ok := dom_hash_map.Load(domain)
		if ok {
			country := val.(string);
			mu.Lock();
			cnt_inter, ok := country_hash.Load(country);
			if(ok){
				cnt :=cnt_inter.(int);
				country_hash.Store(country,cnt+1);
				fmt.Println("Email : ",email," Country: ", parse_country(country), " | Total Country : ",cnt+1)
				save_data(country,email);
				cnt=0;
			}
			mu.Unlock();

		}else{
			whois_info := whois_info(domain);
			if whois_info =="error"{
				continue;
			}
			info := ParseWhois(whois_info);
			dom_hash_map.Store(domain,info.Country);
			mu.Lock();
			if cnt_inter, ok := country_hash.Load(info.Country); ok {
				cnt := cnt_inter.(int);
				country_hash.Store(info.Country,cnt+1);
				fmt.Println("Email : ",email," Country:", parse_country(info.Country)," | Total Country : ",cnt+1)
				save_data(info.Country,email);
				
			}else{
				country_hash.Store(info.Country,1);
			fmt.Println("Email : ",email," Country:", parse_country(info.Country)," | Total Country : ",1)
			save_data(info.Country,email);
			
			}
			mu.Unlock();
			
		}

	}

}

func main()  {
	
	if(len(os.Args)<2){
		fmt.Println("Usage : file name required");
		return;
	}
	input_file := os.Args[1];
	file,err := os.Open(input_file);
	if err != nil {
		fmt.Println("Error opening file:", err);
		return;
	}
	defer file.Close();
	scanner := bufio.NewScanner(file);
	dom_hash_map := sync.Map{};
	country_hash := sync.Map{};
	jobs := make(chan string , 100);
	var wg sync.WaitGroup
	var mu sync.Mutex
	numWorkers := 1
	for i:=1;i<=numWorkers;i++{
		wg.Add(1);
		go workers(&wg,jobs,&dom_hash_map,&country_hash,&mu);
	}
	for scanner.Scan(){
		email := strings.TrimSpace(scanner.Text());
		if email ==""{
			continue;
		}
		jobs <- email;	
		
	}
	close(jobs);
	wg.Wait();
	
}
