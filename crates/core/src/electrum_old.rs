//! Electrum 1.x "old" seed mnemonic (2011-2014): 1626-word list, 3 words per 32-bit group,
//! 12 words = 128-bit hex seed (24 words = 256-bit). Public text: the list and the
//! word <-> hex arithmetic only; the seed stretching and keys live in blocktools-secrets.
//! Source: spesmilo/electrum electrum/old_mnemonic.py (list from the Wiktionary contemporary-poetry
//! frequency list). Decoding per Electrum's mn_decode: x = w1 + n*((w2-w1) mod n) + n*n*((w3-w2) mod n).

pub const N: usize = 1626;
pub const WORDS: [&str; N] = [
    "like", "just", "love", "know", "never", "want", "time", "out", "there", "make", "look", "eye", "down", "only",
    "think", "heart", "back", "then", "into", "about", "more", "away", "still", "them", "take", "thing", "even",
    "through", "long", "always", "world", "too", "friend", "tell", "try", "hand", "thought", "over", "here", "other",
    "need", "smile", "again", "much", "cry", "been", "night", "ever", "little", "said", "end", "some", "those",
    "around", "mind", "people", "girl", "leave", "dream", "left", "turn", "myself", "give", "nothing", "really",
    "off", "before", "something", "find", "walk", "wish", "good", "once", "place", "ask", "stop", "keep", "watch",
    "seem", "everything", "wait", "got", "yet", "made", "remember", "start", "alone", "run", "hope", "maybe",
    "believe", "body", "hate", "after", "close", "talk", "stand", "own", "each", "hurt", "help", "home", "god",
    "soul", "new", "many", "two", "inside", "should", "true", "first", "fear", "mean", "better", "play", "another",
    "gone", "change", "use", "wonder", "someone", "hair", "cold", "open", "best", "any", "behind", "happen", "water",
    "dark", "laugh", "stay", "forever", "name", "work", "show", "sky", "break", "came", "deep", "door", "put",
    "black", "together", "upon", "happy", "such", "great", "white", "matter", "fill", "past", "please", "burn",
    "cause", "enough", "touch", "moment", "soon", "voice", "scream", "anything", "stare", "sound", "red", "everyone",
    "hide", "kiss", "truth", "death", "beautiful", "mine", "blood", "broken", "very", "pass", "next", "forget",
    "tree", "wrong", "air", "mother", "understand", "lip", "hit", "wall", "memory", "sleep", "free", "high",
    "realize", "school", "might", "skin", "sweet", "perfect", "blue", "kill", "breath", "dance", "against", "fly",
    "between", "grow", "strong", "under", "listen", "bring", "sometimes", "speak", "pull", "person", "become",
    "family", "begin", "ground", "real", "small", "father", "sure", "feet", "rest", "young", "finally", "land",
    "across", "today", "different", "guy", "line", "fire", "reason", "reach", "second", "slowly", "write", "eat",
    "smell", "mouth", "step", "learn", "three", "floor", "promise", "breathe", "darkness", "push", "earth", "guess",
    "save", "song", "above", "along", "both", "color", "house", "almost", "sorry", "anymore", "brother", "okay",
    "dear", "game", "fade", "already", "apart", "warm", "beauty", "heard", "notice", "question", "shine", "began",
    "piece", "whole", "shadow", "secret", "street", "within", "finger", "point", "morning", "whisper", "child",
    "moon", "green", "story", "glass", "kid", "silence", "since", "soft", "yourself", "empty", "shall", "angel",
    "answer", "baby", "bright", "dad", "path", "worry", "hour", "drop", "follow", "power", "war", "half", "flow",
    "heaven", "act", "chance", "fact", "least", "tired", "children", "near", "quite", "afraid", "rise", "sea",
    "taste", "window", "cover", "nice", "trust", "lot", "sad", "cool", "force", "peace", "return", "blind", "easy",
    "ready", "roll", "rose", "drive", "held", "music", "beneath", "hang", "mom", "paint", "emotion", "quiet", "clear",
    "cloud", "few", "pretty", "bird", "outside", "paper", "picture", "front", "rock", "simple", "anyone", "meant",
    "reality", "road", "sense", "waste", "bit", "leaf", "thank", "happiness", "meet", "men", "smoke", "truly",
    "decide", "self", "age", "book", "form", "alive", "carry", "escape", "damn", "instead", "able", "ice", "minute",
    "throw", "catch", "leg", "ring", "course", "goodbye", "lead", "poem", "sick", "corner", "desire", "known",
    "problem", "remind", "shoulder", "suppose", "toward", "wave", "drink", "jump", "woman", "pretend", "sister",
    "week", "human", "joy", "crack", "grey", "pray", "surprise", "dry", "knee", "less", "search", "bleed", "caught",
    "clean", "embrace", "future", "king", "son", "sorrow", "chest", "hug", "remain", "sat", "worth", "blow", "daddy",
    "final", "parent", "tight", "also", "create", "lonely", "safe", "cross", "dress", "evil", "silent", "bone",
    "fate", "perhaps", "anger", "class", "scar", "snow", "tiny", "tonight", "continue", "control", "dog", "edge",
    "mirror", "month", "suddenly", "comfort", "given", "loud", "quickly", "gaze", "plan", "rush", "stone", "town",
    "battle", "ignore", "spirit", "stood", "stupid", "yours", "brown", "build", "dust", "hey", "kept", "pay", "phone",
    "twist", "although", "ball", "beyond", "hidden", "nose", "taken", "fail", "float", "pure", "somehow", "wash",
    "wrap", "angry", "cheek", "creature", "forgotten", "heat", "rip", "single", "space", "special", "weak",
    "whatever", "yell", "anyway", "blame", "job", "choose", "country", "curse", "drift", "echo", "figure", "grew",
    "laughter", "neck", "suffer", "worse", "yeah", "disappear", "foot", "forward", "knife", "mess", "somewhere",
    "stomach", "storm", "beg", "idea", "lift", "offer", "breeze", "field", "five", "often", "simply", "stuck", "win",
    "allow", "confuse", "enjoy", "except", "flower", "seek", "strength", "calm", "grin", "gun", "heavy", "hill",
    "large", "ocean", "shoe", "sigh", "straight", "summer", "tongue", "accept", "crazy", "everyday", "exist", "grass",
    "mistake", "sent", "shut", "surround", "table", "ache", "brain", "destroy", "heal", "nature", "shout", "sign",
    "stain", "choice", "doubt", "glance", "glow", "mountain", "queen", "stranger", "throat", "tomorrow", "city",
    "either", "fish", "flame", "rather", "shape", "spin", "spread", "ash", "distance", "finish", "image", "imagine",
    "important", "nobody", "shatter", "warmth", "became", "feed", "flesh", "funny", "lust", "shirt", "trouble",
    "yellow", "attention", "bare", "bite", "money", "protect", "amaze", "appear", "born", "choke", "completely",
    "daughter", "fresh", "friendship", "gentle", "probably", "six", "deserve", "expect", "grab", "middle",
    "nightmare", "river", "thousand", "weight", "worst", "wound", "barely", "bottle", "cream", "regret",
    "relationship", "stick", "test", "crush", "endless", "fault", "itself", "rule", "spill", "art", "circle", "join",
    "kick", "mask", "master", "passion", "quick", "raise", "smooth", "unless", "wander", "actually", "broke", "chair",
    "deal", "favorite", "gift", "note", "number", "sweat", "box", "chill", "clothes", "lady", "mark", "park", "poor",
    "sadness", "tie", "animal", "belong", "brush", "consume", "dawn", "forest", "innocent", "pen", "pride", "stream",
    "thick", "clay", "complete", "count", "draw", "faith", "press", "silver", "struggle", "surface", "taught",
    "teach", "wet", "bless", "chase", "climb", "enter", "letter", "melt", "metal", "movie", "stretch", "swing",
    "vision", "wife", "beside", "crash", "forgot", "guide", "haunt", "joke", "knock", "plant", "pour", "prove",
    "reveal", "steal", "stuff", "trip", "wood", "wrist", "bother", "bottom", "crawl", "crowd", "fix", "forgive",
    "frown", "grace", "loose", "lucky", "party", "release", "surely", "survive", "teacher", "gently", "grip", "speed",
    "suicide", "travel", "treat", "vein", "written", "cage", "chain", "conversation", "date", "enemy", "however",
    "interest", "million", "page", "pink", "proud", "sway", "themselves", "winter", "church", "cruel", "cup", "demon",
    "experience", "freedom", "pair", "pop", "purpose", "respect", "shoot", "softly", "state", "strange", "bar",
    "birth", "curl", "dirt", "excuse", "lord", "lovely", "monster", "order", "pack", "pants", "pool", "scene",
    "seven", "shame", "slide", "ugly", "among", "blade", "blonde", "closet", "creek", "deny", "drug", "eternity",
    "gain", "grade", "handle", "key", "linger", "pale", "prepare", "swallow", "swim", "tremble", "wheel", "won",
    "cast", "cigarette", "claim", "college", "direction", "dirty", "gather", "ghost", "hundred", "loss", "lung",
    "orange", "present", "swear", "swirl", "twice", "wild", "bitter", "blanket", "doctor", "everywhere", "flash",
    "grown", "knowledge", "numb", "pressure", "radio", "repeat", "ruin", "spend", "unknown", "buy", "clock", "devil",
    "early", "false", "fantasy", "pound", "precious", "refuse", "sheet", "teeth", "welcome", "add", "ahead", "block",
    "bury", "caress", "content", "depth", "despite", "distant", "marry", "purple", "threw", "whenever", "bomb",
    "dull", "easily", "grasp", "hospital", "innocence", "normal", "receive", "reply", "rhyme", "shade", "someday",
    "sword", "toe", "visit", "asleep", "bought", "center", "consider", "flat", "hero", "history", "ink", "insane",
    "muscle", "mystery", "pocket", "reflection", "shove", "silently", "smart", "soldier", "spot", "stress", "train",
    "type", "view", "whether", "bus", "energy", "explain", "holy", "hunger", "inch", "magic", "mix", "noise",
    "nowhere", "prayer", "presence", "shock", "snap", "spider", "study", "thunder", "trail", "admit", "agree", "bag",
    "bang", "bound", "butterfly", "cute", "exactly", "explode", "familiar", "fold", "further", "pierce", "reflect",
    "scent", "selfish", "sharp", "sink", "spring", "stumble", "universe", "weep", "women", "wonderful", "action",
    "ancient", "attempt", "avoid", "birthday", "branch", "chocolate", "core", "depress", "drunk", "especially",
    "focus", "fruit", "honest", "match", "palm", "perfectly", "pillow", "pity", "poison", "roar", "shift", "slightly",
    "thump", "truck", "tune", "twenty", "unable", "wipe", "wrote", "coat", "constant", "dinner", "drove", "egg",
    "eternal", "flight", "flood", "frame", "freak", "gasp", "glad", "hollow", "motion", "peer", "plastic", "root",
    "screen", "season", "sting", "strike", "team", "unlike", "victim", "volume", "warn", "weird", "attack", "await",
    "awake", "built", "charm", "crave", "despair", "fought", "grant", "grief", "horse", "limit", "message", "ripple",
    "sanity", "scatter", "serve", "split", "string", "trick", "annoy", "blur", "boat", "brave", "clearly", "cling",
    "connect", "fist", "forth", "imagination", "iron", "jock", "judge", "lesson", "milk", "misery", "nail", "naked",
    "ourselves", "poet", "possible", "princess", "sail", "size", "snake", "society", "stroke", "torture", "toss",
    "trace", "wise", "bloom", "bullet", "cell", "check", "cost", "darling", "during", "footstep", "fragile",
    "hallway", "hardly", "horizon", "invisible", "journey", "midnight", "mud", "nod", "pause", "relax", "shiver",
    "sudden", "value", "youth", "abuse", "admire", "blink", "breast", "bruise", "constantly", "couple", "creep",
    "curve", "difference", "dumb", "emptiness", "gotta", "honor", "plain", "planet", "recall", "rub", "ship", "slam",
    "soar", "somebody", "tightly", "weather", "adore", "approach", "bond", "bread", "burst", "candle", "coffee",
    "cousin", "crime", "desert", "flutter", "frozen", "grand", "heel", "hello", "language", "level", "movement",
    "pleasure", "powerful", "random", "rhythm", "settle", "silly", "slap", "sort", "spoken", "steel", "threaten",
    "tumble", "upset", "aside", "awkward", "bee", "blank", "board", "button", "card", "carefully", "complain", "crap",
    "deeply", "discover", "drag", "dread", "effort", "entire", "fairy", "giant", "gotten", "greet", "illusion",
    "jeans", "leap", "liquid", "march", "mend", "nervous", "nine", "replace", "rope", "spine", "stole", "terror",
    "accident", "apple", "balance", "boom", "childhood", "collect", "demand", "depression", "eventually", "faint",
    "glare", "goal", "group", "honey", "kitchen", "laid", "limb", "machine", "mere", "mold", "murder", "nerve",
    "painful", "poetry", "prince", "rabbit", "shelter", "shore", "shower", "soothe", "stair", "steady", "sunlight",
    "tangle", "tease", "treasure", "uncle", "begun", "bliss", "canvas", "cheer", "claw", "clutch", "commit",
    "crimson", "crystal", "delight", "doll", "existence", "express", "fog", "football", "gay", "goose", "guard",
    "hatred", "illuminate", "mass", "math", "mourn", "rich", "rough", "skip", "stir", "student", "style", "support",
    "thorn", "tough", "yard", "yearn", "yesterday", "advice", "appreciate", "autumn", "bank", "beam", "bowl",
    "capture", "carve", "collapse", "confusion", "creation", "dove", "feather", "girlfriend", "glory", "government",
    "harsh", "hop", "inner", "loser", "moonlight", "neighbor", "neither", "peach", "pig", "praise", "screw", "shield",
    "shimmer", "sneak", "stab", "subject", "throughout", "thrown", "tower", "twirl", "wow", "army", "arrive",
    "bathroom", "bump", "cease", "cookie", "couch", "courage", "dim", "guilt", "howl", "hum", "husband", "insult",
    "led", "lunch", "mock", "mostly", "natural", "nearly", "needle", "nerd", "peaceful", "perfection", "pile",
    "price", "remove", "roam", "sanctuary", "serious", "shiny", "shook", "sob", "stolen", "tap", "vain", "void",
    "warrior", "wrinkle", "affection", "apologize", "blossom", "bounce", "bridge", "cheap", "crumble", "decision",
    "descend", "desperately", "dig", "dot", "flip", "frighten", "heartbeat", "huge", "lazy", "lick", "odd", "opinion",
    "process", "puzzle", "quietly", "retreat", "score", "sentence", "separate", "situation", "skill", "soak",
    "square", "stray", "taint", "task", "tide", "underneath", "veil", "whistle", "anywhere", "bedroom", "bid",
    "bloody", "burden", "careful", "compare", "concern", "curtain", "decay", "defeat", "describe", "double",
    "dreamer", "driver", "dwell", "evening", "flare", "flicker", "grandma", "guitar", "harm", "horrible", "hungry",
    "indeed", "lace", "melody", "monkey", "nation", "object", "obviously", "rainbow", "salt", "scratch", "shown",
    "shy", "stage", "stun", "third", "tickle", "useless", "weakness", "worship", "worthless", "afternoon", "beard",
    "boyfriend", "bubble", "busy", "certain", "chin", "concrete", "desk", "diamond", "doom", "drawn", "due",
    "felicity", "freeze", "frost", "garden", "glide", "harmony", "hopefully", "hunt", "jealous", "lightning", "mama",
    "mercy", "peel", "physical", "position", "pulse", "punch", "quit", "rant", "respond", "salty", "sane", "satisfy",
    "savior", "sheep", "slept", "social", "sport", "tuck", "utter", "valley", "wolf", "aim", "alas", "alter", "arrow",
    "awaken", "beaten", "belief", "brand", "ceiling", "cheese", "clue", "confidence", "connection", "daily",
    "disguise", "eager", "erase", "essence", "everytime", "expression", "fan", "flag", "flirt", "foul", "fur",
    "giggle", "glorious", "ignorance", "law", "lifeless", "measure", "mighty", "muse", "north", "opposite",
    "paradise", "patience", "patient", "pencil", "petal", "plate", "ponder", "possibly", "practice", "slice", "spell",
    "stock", "strife", "strip", "suffocate", "suit", "tender", "tool", "trade", "velvet", "verse", "waist", "witch",
    "aunt", "bench", "bold", "cap", "certainly", "click", "companion", "creator", "dart", "delicate", "determine",
    "dish", "dragon", "drama", "drum", "dude", "everybody", "feast", "forehead", "former", "fright", "fully", "gas",
    "hook", "hurl", "invite", "juice", "manage", "moral", "possess", "raw", "rebel", "royal", "scale", "scary",
    "several", "slight", "stubborn", "swell", "talent", "tea", "terrible", "thread", "torment", "trickle", "usually",
    "vast", "violence", "weave", "acid", "agony", "ashamed", "awe", "belly", "blend", "blush", "character", "cheat",
    "common", "company", "coward", "creak", "danger", "deadly", "defense", "define", "depend", "desperate",
    "destination", "dew", "duck", "dusty", "embarrass", "engine", "example", "explore", "foe", "freely", "frustrate",
    "generation", "glove", "guilty", "health", "hurry", "idiot", "impossible", "inhale", "jaw", "kingdom", "mention",
    "mist", "moan", "mumble", "mutter", "observe", "ode", "pathetic", "pattern", "pie", "prefer", "puff", "rape",
    "rare", "revenge", "rude", "scrape", "spiral", "squeeze", "strain", "sunset", "suspend", "sympathy", "thigh",
    "throne", "total", "unseen", "weapon", "weary",
];

/// Index of a word in the old list (case-insensitive ASCII).
pub fn index(w: &str) -> Option<usize> {
    let l = w.to_ascii_lowercase();
    WORDS.iter().position(|x| *x == l)
}
/// Old-Electrum words -> hex seed (8 hex chars per 3 words). None unless every word is in the
/// list and the count is 12 or 24 (Electrum's is_old_seed).
pub fn decode(words: &[&str]) -> Option<String> {
    if words.len() != 12 && words.len() != 24 { return None }
    let n = N as u64;
    let mut out = String::with_capacity(words.len() / 3 * 8);
    for g in words.chunks(3) {
        let (w1, w2, w3) = (index(g[0])? as u64, index(g[1])? as u64, index(g[2])? as u64);
        let x = w1 + n * ((w2 + n - w1) % n) + n * n * ((w3 + n - w2) % n);
        out.push_str(&format!("{x:08x}"));
    }
    Some(out)
}
/// Hex seed (32 or 64 hex chars) -> old-Electrum words (Electrum's mn_encode); for tests and reports.
pub fn encode(hex: &str) -> Option<Vec<&'static str>> {
    if hex.len() != 32 && hex.len() != 64 { return None }
    let n = hex.len() / 8;
    let mut out = Vec::with_capacity(n * 3);
    for i in 0..n {
        let x = u64::from_str_radix(&hex[8 * i..8 * i + 8], 16).ok()?;
        let w1 = x % N as u64;
        let w2 = (x / N as u64 + w1) % N as u64;
        let w3 = (x / N as u64 / N as u64 + w2) % N as u64;
        out.extend([WORDS[w1 as usize], WORDS[w2 as usize], WORDS[w3 as usize]]);
    }
    Some(out)
}
/// True for a phrase of 12 or 24 old-list words, or a bare 32/64-hex old seed.
pub fn is_old_seed(phrase: &str) -> bool {
    let t = phrase.trim();
    let w: Vec<&str> = t.split_whitespace().collect();
    if w.len() == 1 { return (t.len() == 32 || t.len() == 64) && t.bytes().all(|b| b.is_ascii_hexdigit()) }
    decode(&w).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn list_shape() {
        assert_eq!(WORDS.len(), 1626);
        let mut s: Vec<&str> = WORDS.to_vec(); s.sort(); s.dedup(); assert_eq!(s.len(), 1626);
        assert_eq!((WORDS[0], WORDS[1], WORDS[1625]), ("like", "just", "weary"));
    }
    /// Electrum's test_wallet_vertical.py test_electrum_seed_old: words <-> hex seed (public test vector).
    #[test] fn electrum_old_vector() {
        let w = "powerful random nobody notice nothing important anyway look away hidden message over";
        let ws: Vec<&str> = w.split(' ').collect();
        assert_eq!(decode(&ws).as_deref(), Some("acb740e454c3134901d7c8f16497cc1c"));
        assert_eq!(encode("acb740e454c3134901d7c8f16497cc1c").unwrap().join(" "), w);
        assert!(is_old_seed(w) && is_old_seed("acb740e454c3134901d7c8f16497cc1c") && is_old_seed(&w.to_uppercase()));
        assert!(!is_old_seed("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"));
        assert!(!is_old_seed("powerful random nobody notice nothing important anyway look away hidden message"));
    }
    #[test] fn roundtrip_edges() {
        for h in ["00000000000000000000000000000000", "ffffffffffffffffffffffffffffffff", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"] {
            let w = encode(h).unwrap(); assert_eq!(decode(&w).unwrap(), h);
        }
    }
}
