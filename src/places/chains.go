package places

import (
	"strings"
	"unicode"
)

var diacriticReplacer = strings.NewReplacer(
	"á", "a", "à", "a", "ä", "a", "â", "a", "ã", "a",
	"é", "e", "è", "e", "ê", "e", "ë", "e",
	"í", "i", "ì", "i", "î", "i", "ï", "i",
	"ó", "o", "ò", "o", "ô", "o", "ö", "o", "õ", "o",
	"ú", "u", "ù", "u", "û", "u", "ü", "u",
	"ñ", "n", "ç", "c", "œ", "oe", "ø", "o",
	"’", "'", "‘", "'", "“", "\"", "”", "\"",
)

var bigChainNames = []string{
	"costa coffee",
	"caffe nero",
	"pret a manger",
	"tim hortons",
	"mcdonalds",
	"kfc",
	"subway",
	"greggs",
	"pizza express",
	"zizzi",
	"ask italian",
	"piccolino",
	"riva blu",
	"rudys pizza",
	"circolo popolare",
	"five guys",
	"honest burgers",
	"almost famous",
	"hard rock cafe",
	"tgi fridays",
	"miller and carter",
	"gaucho",
	"hawksmoor",
	"blacklock",
	"wagamama",
	"pho",
	"nandos",
	"dishoom",
	"mowgli",
	"turtle bay",
	"the ivy",
	"the alchemist",
	"the botanist",
	"revolucion de cuba",
	"slug and lettuce",
	"all bar one",
	"be at one",
	"cosy club",
	"flight club",
	"jd wetherspoon",
	"greene king",
	"nicholsons pubs",
	"heytea",
	"starbucks",
	"dominos pizza",
	"pizza hut",
	"burger king",
	"papa johns",
	"taco bell",
	"krispy kreme",
	"patisserie valerie",
	"prezzo",
	"bella italia",
	"carluccios",
	"franco manca",
	"strada",
	"itsu",
	"wasabi",
	"yo sushi",
	"chopstix",
	"the real greek",
	"chiquito",
	"las iguanas",
	"tortilla",
	"cafe rouge",
	"cote",
	"brasserie blanc",
	"gourmet burger kitchen",
	"gbk",
	"byron",
	"shake shack",
	"frankie and bennys",
	"bills",
	"giraffe world kitchen",
	"leon",
	"toby carvery",
	"harvester",
	"sizzling pubs",
	"ember inns",
	"stonehouse pizza and carvery",
	"crown carveries",
	"oneills",
	"vintage inns",
	"browns brasserie and bar",
	"beefeater",
	"brewers fayre",
	"table table",
	"loungers",
	"coppa club",
	"eds easy diner",
	"banana tree",
	"gails",
}

var bigChainSet = createBigChainSet()

func createBigChainSet() map[string]struct{} {
	set := make(map[string]struct{}, len(bigChainNames))
	for _, name := range bigChainNames {
		set[name] = struct{}{}
	}
	return set
}

func normalizeName(raw string) string {
	if raw == "" {
		return ""
	}
	s := strings.ToLower(strings.TrimSpace(raw))
	s = diacriticReplacer.Replace(s)
	s = strings.ReplaceAll(s, "&", " and ")
	builder := strings.Builder{}
	builder.Grow(len(s))
	for _, r := range s {
		switch {
		case unicode.IsLetter(r), unicode.IsDigit(r):
			builder.WriteRune(unicode.ToLower(r))
		case unicode.IsSpace(r):
			builder.WriteRune(' ')
		}
	}
	collapsed := strings.Join(strings.Fields(builder.String()), " ")
	return collapsed
}

func isBigChain(name string) bool {
	normalized := normalizeName(name)
	if normalized == "" {
		return false
	}
	for chain := range bigChainSet {
		if strings.Contains(normalized, chain) {
			return true
		}
	}
	return false
}
