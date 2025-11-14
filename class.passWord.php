<?php

class passWord {
  
  /** ****************
  * Added: 4.0
  * Description: Version Constant
  **************** */  
  const VERSION = '5.0.0';
  
  /** ****************
  * Added: 4.0
  * Description: title constant
  **************** */
  const TITLE = 'Password Class';
  
  
  private $hashType;
  private $salt;
  private $cypherText;
  private $password;
  
  /** ****************
  * Added: 4.0
  * Description: Used to set the Abosulite Max for the number of characters allowed in password generator
  **************** */
  private $absMax = 255;
  
  /** ****************
  * Added: 4.0
  * Description: Used to set the Abosulite Min for the number of characters allowed in password generator
  **************** */
  private $absMin = 3;
  
  /** ****************
  * Added: 1.0
  * Description: Default settings incase no settings are passed to the class 
  **************** */
  private $settings = array(
    'minChar' => 7, 'maxChar' => 32, 'req' => array( 'upper' => true, 'lower' => true, 'num' => true, 'specs' => true),
    'upper' => "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 'lower' => "abcdefghijklmnopqrstuvwxyz", 'num' => "0123456789", 'specs' => "!@#$%^&*.[]{},;=+_-()~|",
    'disallowed' => "/:`'\"\\<>", 'numPasswords' => 1
  );


  /** ****************
  * Added: 4.0
  * Description: Types variable; used to pass default settings to class durring construction
  **************** */
  private $types = array(
    'secure' => array( 'minChar' => 16, 'maxChar' => 32, 'req' => array('upper' => true, 'lower' => true, 'num' => true, 'specs' => false)),
    'hex' => array('req' => array('upper' => false, 'lower' => true, 'num' => true, 'specs' => false), 'lower' => 'abcdef', 'num' => '0123456789'),
    'lower' => array('minChar' => 8, 'maxChar' => 20, 'req' => array( 'upper' => false, 'lower' => true, 'num' => false, 'specs' => false)),
    'crazy' => array( 'minChar' => 30, 'maxChar' => 50, 'req' => array('upper' => true, 'lower' => true, 'num' => true, 'specs' => true)));

  /** ****************
  * Added: 4.0
  * Description: Use to remove any unsupoorted characters from the variable that is being converted in phonetic function 
  **************** */
  private $normalizeChars = array(
    'Á' => 'A', 'À' => 'A', 'Â' => 'A', 'Ã' => 'A', 'Å' => 'A', 'Ä' => 'A', 'Æ' => 'A', 'Ç' => 'C', 'É' => 'E', 'È' => 'E', 'Ê' => 'E', 'Ë' => 'E',
    'Í' => 'I', 'Ì' => 'I', 'Î' => 'I', 'Ï' => 'I', 'Ð' => 'D', 'Ñ' => 'N', 'Ó' => 'O', 'Ò' => 'O', 'Ô' => 'O', 'Õ' => 'O', 'Ö' => 'O', 'Ø' => 'O',
    'Ú' => 'U', 'Ù' => 'U', 'Û' => 'U', 'Ü' => 'U', 'Ý' => 'Y', 'á' => 'a', 'à' => 'a', 'â' => 'a', 'ã' => 'a', 'å' => 'a', 'ä' => 'a', 'æ' => 'a',
    'ç' => 'c', 'é' => 'e', 'è' => 'e', 'ê' => 'e', 'ë' => 'e', 'í' => 'i', 'ì' => 'i', 'î' => 'i', 'ï' => 'i', 'ð' => 'e', 'ñ' => 'n', 'ó' => 'o',
    'ò' => 'o', 'ô' => 'o', 'õ' => 'o', 'ö' => 'o', 'ø' => 'o', 'ú' => 'u', 'ù' => 'u', 'û' => 'u', 'ü' => 'u', 'ý' => 'y', 'ß' => 's', 'þ' => 't',
    'ÿ' => 'y');


  /** ****************
  * Added: 4.0
  * Description:  Phonetic Array used to convert characters to words
  **************** */
  private $phoneticArr = array(
    'normal' => array(
      "a" => "Adam", "b" => "Boy", "c" => "Charles", "d" => "David", "e" => "Edward", "f" => "Frank", "g" => "George", "h" => "Henry", "i" => "Ida",
      "j" => "John", "k" => "King", "l" => "Lincoln", "m" => "Mary", "n" => "Nora", "o" => "Ocean", "p" => "Paul", "q" => "Queen", "r" => "Robert",
      "s" => "Sam", "t" => "Tom", "u" => "Union", "v" => "Victor", "w" => "William", "x" => "X-ray", "y" => "Young", "z" => "Zebra", "0" => "Zero",
      "1" => "One", "2" => "Two", "3" => "Three", "4" => "Four", "5" => "Five", "6" => "Six", "7" => "Seven", "8" => "Eight", "9" => "Nine"),
    'morseCode' => array(
      'a' => '.– ', 'b' => '-... ', 'c' => '-.-. ', 'd' => '-.. ', 'e' => '. ', 'f' => '..-. ', 'g' => '--. ', 'h' => '.... ', 'i' => '.. ',
      'j' => '.--- ', 'k' => '-.- ', 'l' => '.-.. ', 'm' => '-- ', 'n' => '-. ', 'o' => '--- ', 'p' => '.--. ', 'q' => '--.- ', 'r' => '.-. ',
      's' => '... ', 't' => '- ', 'u' => '..- ', 'v' => '...- ', 'w' => '.-- ', 'x' => '-..- ', 'y' => '-.-- ', 'z' => '--.. ', '0' => '----- ',
      '1' => '.---- ', '2' => '..--- ', '3' => '...-- ', '4' => '....- ', '5' => '..... ', '6' => '-.... ', '7' => '--... ', '8' => '---.. ',
      '9' => '----. ', '.' => '.-.-.- ', ',' => '--..-- ', '?' => '..--.. ', '\'' => '.----. ', '!' => '-.-.-- ', '/' => '-..-. ', '(' => '-.--. ',
      ')' => '-.--.- ', '&' => '.-... ', ':' => '---... ', ';' => '-.-.-. ', '=' => '-...- ', '+' => '.-.-. ', '-' => '-....- ', '_' => '..--.- ',
      '"' => '.-..-. ', '$' => '...-..- ', '@' => '.--.-.'),
    'military' => array(
      "a" => "Alpha", "b" => "Bravo", "c" => "Charlie", "d" => "Delta", "e" => "Echo", "f" => "Foxtrot", "g" => "Golf", "h" => "Hotel", "i" => "India",
      "j" => "Juliett", "k" => "Kilo", "l" => "Lima", "m" => "Mike", "n" => "November", "o" => "Oscar", "p" => "Papa", "q" => "Quebec", "r" => "Romeo",
      "s" => "Sierra", "t" => "Tango", "u" => "Uniform", "v" => "Victor", "w" => "Whiskey", "x" => "X-ray", "y" => "Yankee", "z" => "Zulu"),
    'countries' => array(
      'a' => array('Afghanistan', 'Aland', 'Albania', 'Algeria', 'American Samoa', 'Andorra', 'Angola', 'Anguilla', 'Antigua and Barbuda', 'Argentina', 'Armenia', 'Aruba', 'Australia', 'Austria', 'Azerbaijan'),
      'b' => array('Bahamas', 'Bahrain', 'Bangladesh', 'Barbados', 'Belarus', 'Belgium', 'Belize', 'Benin', 'Bermuda', 'Bhutan', 'Bolivia', 'Bosnia-Herzegovina', 'Botswana', 'Bouvet Island', 'Brazil', 'Brunei', 'Bulgaria', 'Burkina Faso', 'Burundi'),
      'c' => array('Cambodia', 'Cameroon', 'Canada', 'Cape Verde', 'Cayman Islands', 'Central African Republic', 'Chad', 'Chile', 'China', 'Christmas Island', 'Cocos Islands', 'Colombia', 'Comoros', 'Congo Democratic Republic of the Zaire', 'Congo Republic of', 'Cook Islands', 'Costa Rica', 'Croatia', 'Cuba', 'Cyprus', 'Czech Republic'),
      'd' => array('Denmark', 'Djibouti', 'Dominica', 'Dominican Republic'),
      'e' => array('Ecuador', 'Egypt', 'El Salvador', 'Equatorial Guinea', 'Eritrea', 'Estonia', 'Ethiopia'),
      'f' => array('Falkland Islands', 'Faroe Islands', 'Fiji', 'Finland', 'France', 'French'),
      'g' => array('Gabon', 'Gambia', 'Georgia', 'Germany', 'Ghana', 'Gibraltar', 'Greece', 'Greenland', 'Grenada', 'Guadeloupe', 'Guam', 'Guatemala', 'Guinea', 'Guinea Bissau', 'Guyana'),
      'h' => array('Haiti', 'Holy See', 'Honduras', 'Hong Kong', 'Hungary'),
      'i' => array('Iceland', 'India', 'Indonesia', 'Iran', 'Iraq', 'Ireland', 'Israel', 'Italy', 'Ivory Coast'),
      'j' => array('Jamaica', 'Japan', 'Jordan'),
      'k' => array('Kazakhstan', 'Kenya', 'Kiribati', 'Kuwait', 'Kyrgyzstan'),
      'l' => array('Laos', 'Latvia', 'Lebanon', 'Lesotho', 'Liberia', 'Libya', 'Liechtenstein', 'Lithuania', 'Luxembourg'),
      'm' => array('Macau', 'Macedonia', 'Madagascar', 'Malawi', 'Malaysia', 'Maldives', 'Mali', 'Malta', 'Marshall Islands', 'Martinique', 'Mauritania', 'Mauritius', 'Mayotte', 'Mexico', 'Micronesia', 'Moldova', 'Monaco', 'Mongolia', 'Montenegro', 'Montserrat', 'Morocco', 'Mozambique', 'Myanmar'),
      'n' => array('Netherlands' ,'Netherlands Antilles' ,'New Caledonia', 'New Zealand', 'Nicaragua' ,'Niger', 'Nigeria', 'Niue', 'Norfolk Island', 'North Korea', 'Northern Mariana Islands', 'Norway'),
      'o' => array('Oman'),
      'p' => array('Pakistan', 'Palau', 'Panama', 'Papua New Guinea', 'Paraguay', 'Peru', 'Philippines', 'Pitcairn Island', 'Poland', 'Polynesia', 'Portugal', 'Puerto Rico'),
      'q' => array('Qatar'),
      'r' => array('Reunion', 'Romania', 'Russia', 'Rwanda'),
      's' => array('Saint Helena', 'Saint Kitts and Nevis', 'Saint Lucia', 'Saint Pierre and Miquelon', 'Saint Vincent and Grenadines', 'Samoa', 'San Marino', 'Sao Tome and Principe', 'Saudi Arabia', 'Senegal', 'Serbia', 'Seychelles', 'Sierra Leone', 'Singapore', 'Slovakia', 'Slovenia', 'Solomon Islands',
      'Somalia' ,'South Africa', 'South Georgia and South Sandwich Islands', 'South Korea', 'Spain', 'Sri Lanka', 'Sudan', 'Suriname', 'Svalbard and Jan Mayen Islands', 'Swaziland', 'Sweden', 'Switzerland', 'Syria'),
      't' => array('Taiwan', 'Tajikistan', 'Tanzania', 'Thailand', 'Timor-Leste', 'Togo', 'Tokelau', 'Tonga', 'Trinidad and Tobago', 'Tunisia', 'Turkey', 'Turkmenistan', 'Turks and Caicos Islands', 'Tuvalu'),
      'u' => array('Uganda', 'Ukraine', 'United Arab Emirates', 'United Kingdom', 'United States', 'Uruguay	South', 'Uzbekistan'),
      'v' => array('Vanuatu', 'Venezuela', 'Vietnam	Asia', 'Virgin'),
      'w' => array('Wallis and Futuna Islands'),
      'y' => array('Yemen'),
      'z' => array('Zambia', 'Zimbabwe'),
      ),
    'stores' => array(
      'a' => 'apple', 'b' => 'bestbuy', 'c' => 'cost plus', 'd' => 'dicks sporting goods', 'e' => 'express', 'f' => 'frys', 'g' => 'gap',
      'h' => 'home depot', 'i' => 'ikea', 'j' => 'jcpenny', 'k' => 'kohl', 'l' => 'lowes', 'm' => 'macys', 'n' => 'nordstrom', 'o' => 'office max',
      'p' => 'petsmart', 'q' => 'quiznos', 'r' => 'rite aid', 's' => 'sees candy', 't' => 'target', 'u' => 'ups', 'v' => 'vitamin shoppe',
      'w' => 'walmart', 'x' => 'x-ryderz', 'y' => 'yankee candle', 'z' => 'zumiez')
      );
      
      /** ****************
      * Added: 4.0
      * Description: Top 10,000 most common passwords have been removed; add your own list of common passwords here
      **************** */
      protected $commonPasswords = array("Add", "your", "own", "password", "list", "here", "as", "an", "array");

  
  /**
   * Magic functions --------------------------------------------------------------------------------------------------------------
  */
  
  /** ****************
  * Added: 1.0
  * Description: Constructor  for passWord class; can pass a type string or add and declare a custom type
  * Example:
  * $p = new passWord('custom', array('custom' => array('minChar' => 30, 'maxChar' => 31)));
  * 
  * $p is now a passWord object with all default settings except now the minimum characters is 30 and max is 31
  **************** */
  function __construct($type = "", $typeArr = array()) {
    /** 
     * Check if $typeArr is an array and not empty
     * if it isn't empty then the array will be set as an available type'    
    */
    if (!empty($typeArr) && gettype($typeArr) == "array") {
      $this->addType($typeArr);
    }
    /**
     * Check if $type is a string
     * if string isn't empty then the type will be set 
    */
    if (!empty($type) && gettype($type) == "string") {
      $this->_setType($type);
    }
  }
  
  /** ****************
  * Added: 4.0
  * Description: will return a single password when the password class is called like a string variable
  * Example:
  * $pw = new passWord();
  * echo $pw; will echo a single password
  **************** */
  public function __toString() {
    
    /** Will return a string of a single password; */
    return $this->singlePassword();
  }
  
  /** ****************
  * Added: 4.0
  * Description: overloading the __get method to allow easy access to the settings
  * Example:
  * $pw = new passWord();
  * echo $pw->numPasswords; //because numPasswords isn't a variable of passWords class the __get method is called and returns settings['numPasswords'];
  **************** */
  public function __get($name) {
    
    /** checks if the $name is in the settings array */
    if (array_key_exists($name, $this->settings)) {
        
        /** if it is then return the value of $name */
        return $this->settings[$name];
    }
    
    /** else return null */
    return null;
  }
  
  /** ****************
  * Added: 4.0
  * Description: overloading __set to make settings one of the settings easy
  * Example:
  * $pw = new passWord();
  * $pw->numPasswords = 3;
  **************** */
  public function __set($name, $value) {
    
    /** check if $name exists in $this->settings; */
    if (array_key_exists($name, $this->settings)) {
        
        /** if it does then set the value to the passed value */
        $this->settings(array($name => $value));
    }
  }
  
  /** ****************
  * Added: 4.0
  * Description: will return true/false if the variable $name exists in the array $this->settings;
  * called when a variable is checked to see if it is set and it isn't an already available variable
  * Example:
  * $pw = new passWord();
  * echo isset($pw->numPasswords) ? 'true' : 'false';
  **************** */
  public function __isset($name) {
    return array_key_exists($name, $this->settings);
  }
  
  /** ****************
  * Added: 4.0
  * Description: used when the function is called like a function; will only allow for easy setting of settings
  * Example:
  * $pw = new passWord();
  * $pw($settings);
  **************** */
  public function __invoke($settings) {
    $this->settings($settings);
  }
  /**
   * End Magic functions --------------------------------------------------------------------------------------------------------------
  */
  
  
  /**
   * Private functions --------------------------------------------------------------------------------------------------------------
  */
  
  /** ****************
    * Added: 4.0
    * Description: Private function used as handler to return character types to formatedPassword function; needed for {3} function 
    * Example:
    * $pw->_CharType('UC')
    * *Return*: B
    **************** */
    private function _CharType($charType) {
        
        /** switch statement to chose an option based on inputed variable */
        switch ($charType) {
            
            /** if variable is UC then return an uppercase character */
               case 'UC':
                   return $this->_getChar('upper');
               break;
               
            /** if $charType is LC then return a lowercase letter */
               case 'LC':
                   return $this->_getChar('lower');
               break;
            /** if $charType is N then return a number */
               case 'N':
                   return $this->_getChar('num');
               break;
            /** if $charType is S then return a special character */
               case 'S':
                   return $this->_getChar('specs');
               break;
            /** if $charType is RA then return a random character */
               case 'RA':
                   $tmp = array('upper', 'lower', 'num', 'specs');
                   return $this->_getChar($tmp[array_rand($tmp)]);
               break;
            /** if $charType is UL then return a random character */
               case 'UL':
                   $tmp = array('upper', 'lower');
                   return $this->_getChar($tmp[array_rand($tmp)]);
               break;
            /** if $charType is in the [xxxxx] format then return one of the passed letters */
               default:
               
                   /** Match the [xxx] format */
                   if (preg_match('/^\[[^\]]+\]$/m', $charType)) {
                    
                     /** remove [ and ] from [xxxxx] string */
                     $charType = substr($charType, 1, -1);
                     
                     /** return a random character from the string */
                     return $charType[rand(0, (strlen($charType)-1))];
                   }
               break;
        }
        
        /** if nothing matches then return function with no value */
        return;
    }
  
  /** ****************
  * Added: 4.0
  * Description: Debuging function for true/false variables - to be removed before production release 
  * Example:
  * $pw->_DebugBool($validated, 'valid');
  * *Output*: valid : False
  **************** */
  public function _DebugBool($bool, $name) {
    echo $name . ' : ' . ($bool ? 'True' : 'False') . ';<br />';
  }
  
  /** ****************
  * Added: 3.0
  * Description: Used to get a random character from the array of characters available in the $this->settings
  * Example:
  * $pw->_getChar('upper')
  * *output* B;
  **************** */
  private function _getChar($t) {
    
    /** return false if the passed variable isn't a string or is empty */
    if (empty($t) || gettype($t) != 'string') { return false; }
    /** return a random character if the passed string is a required item */
    return $this->_isAllowed($t) ? substr($this->settings[$t], mt_rand(0, strlen($this->settings[$t]) - 1), 1) : null;
  }
  
  /** ****************
  * Added: 3.0
  * Description: Check if the required item (passed in $t) is allowed/required
  **************** */
  private function _isAllowed($t) { return ($t == 'upper' || $t == 'lower' || $t == 'num' || $t == 'specs') && $this->settings['req'][$t]; }
  
  /** ****************
  * Added: 4.0
  * Description: Function used to replace any characters that aren't valid with valid characters 
  * Example: N/A - internal function
  **************** */
  private function _normalize($str) { return strtr($str, $this->normalizeChars); }
  
  /** ****************
  * Added: 1.0
  * Description: remove any characters that are not allowed; so even if the character is passed in the available char
  **************** */
  private function _removeDisallowed() {
    
    /** Loop through each character in the dissallowed string */
    for ($l = 0; $l < strlen($this->settings['disallowed']) - 1; $l++) {
        
      /** Get Disallowed Character */
      $dChar = substr($this->settings['disallowed'], $l, 1);
      
      /** check if disallowed character is in the string of accepted charcters - if it is then remove it */
      if (strpos($this->settings['lower'], $dChar) !== false) { $this->settings['lower'] = str_replace($dChar, '', $this->settings['lower']); }
      if (strpos($this->settings['upper'], $dChar) !== false) { $this->settings['upper'] = str_replace($dChar, '', $this->settings['upper']); }
      if (strpos($this->settings['num'], $dChar) !== false) { $this->settings['num'] = str_replace($dChar, '', $this->settings['num']); }
      if (strpos($this->settings['specs'], $dChar) !== false) { $this->settings['specs'] = str_replace($dChar, '', $this->settings['specs']); }
    }
  }
  
  /** ****************
  * Added: 3.0
  * Description: Sets the passed $type if it is set in the $this->types variable 
  * Example:
  * $pw->_setType('secure'); //configures 'secure' pre-configured settings in class
  **************** */
  private function _setType($type) {
    
    /** if $type isn't a string or is empty then return false */
    if (empty($type) || gettype($type) != 'string') { return false; }
    
    /** if the type has been set - then add settings via settings function */
    if (array_key_exists($type, $this->types)) { $this->settings($this->types[$type]); }
  }
  
  /**
   * END Private functions --------------------------------------------------------------------------------------------------------------
  */
  
  /**
   * Password functions --------------------------------------------------------------------------------------------------------------
  */
  
  /** ****************
    * Description: $split input into text block and return random char based on input
    * Example: pw('{UC}{LC}{RA|S}{[aeiou]}') //output should be an uppercase char followed by a lower case letter, then random or special and a random out of the string
    **************** */
    public function formatedPassword($input) {
        
        /** return array */
        $rArray = array();
        
        /** valid "character types" */
        $validChars = array('UC', 'LC', 'N', 'S', 'RA', 'UL');
        
        /** extract each set of curly brackets into $results */
        preg_match_all('/([^{}]*?)\}/', $input, $results, PREG_PATTERN_ORDER);
        
        /** removed everything except the text matches (everything in the curly brackets) */
        $results = $results[1];
        
        /** used if foreach loop to provide previous character type */
        $prevType = '';
        
        /** loop through array of matches */
        foreach ($results as $r) {
            /** split of the string inside the {} incase multiple charTypes were passed */
            preg_match_all('/([[].*?[\]])|(\w)+/', $r, $charTypes, PREG_PATTERN_ORDER);
            
            /** remove everything that isn't a character type */
            $charTypes = $charTypes[0];
            
            /** reset selectedChartype */
            $selectedCharType = '';
            
            /** if there are multiple charTypes then get a random one, otherwise return the only passed charType */
            if(count($charTypes) == 1) {
                /** if only one character type was passed then use that one */
                $selectedCharType = $charTypes[0];
            } else {
                /** if multiple charactertypes were passed then that one will be used; */
                $selectedCharType = $charTypes[array_rand($charTypes)];
            }
            
            /** if the selectedchartype is a number below 256 */
            if (ctype_digit($selectedCharType) && $prevType != '' && $selectedCharType < 256) {
                
                /** loop for x number of times */
                for ($l = 1;$l < $selectedCharType; $l++) {
                
                    /** add previous character type to return array */
                    $rArray[] = $this->_CharType($prevType);
                }
                
                /** reset previous type to prevent multiple previous types */
                $prevType = '';
                
                /** else if $selectCharType is valid */
            } else if (in_array($selectedCharType, $validChars) || preg_match('/^\[.+\]\Z/m', $selectedCharType)) {
                
                /** change previous type */
                $prevType = $selectedCharType;
                
                /** add $selectedchartype to return arry */
                $rArray[] = $this->_CharType($selectedCharType);
            }
        }
        
        /** merge and return $rArray */
        return implode($rArray);
    }
  
  /** ****************
  * Added: 1.0
  * Description: Function used to generate a password; the generated password is returned in an array to support multiple password generatorion;
  *              settings can also be passed into the function 
  * Example:
  * $pw->genPass(); //generate password with previously set settings
  * $pw->genPass(array('minChar' => 19, 'maxChar' => 20)) //pass the maxChar setting and set it to 20 and minChar to 19
  * 
  * *output*: array('kl5#$5jk3pwo')
  * *output*: array('df56143451$eThs#t2')
  **************** */
  public function genPass($settings = array()) {
    
    /** if settings is not empty and an array then set passed settings */
    if (!empty($settings) && gettype($settings) == 'array') { $this->settings($settings); }
    
    /** Set array of valid character types to blank to prevent isuses with multiple passowrd generation call issues  */
    $ok = array();
    
    /** Loop the the setting['req'] array and see if there any enabled */
    foreach ($this->settings['req'] as $k => $v) {
      ($v) ? $ok[] = $k : null;
    }
    /** if no character types are enabled the function will end */
    if (empty($ok)) { return false; }
    
    /** remove any characters that are not allowed
     * Note: possibly move code to this location and remove $this->removeD_isAllowed function - possibly not used    
     */
    $this->_removeDisallowed();
    
    /** Reset Password array incase getPass has been called multiple times */
    $this->password = array();
    
    /** loop through password generation code */
    for ($c = 0; $c < $this->settings['numPasswords']; $c++) {
        
        $numChar = 7;
        /** check if the number of characters is a valid range (min smaller that Max), generate a random number between the two if it is */
        if ($this->settings['maxChar'] > $this->settings['minChar']) {
            /** set $numChar to a random number between min/maxChar */
            $numChar = rand($this->settings['minChar'], $this->settings['maxChar']);
            
        /** if the min and maxChar are equal */
        } elseif ($this->settings['maxChar'] == $this->settings['minChar']) {
            
            /** set $num Char to min if min and max are the same */
            $numChar = $this->settings['minChar'];
        
        /** if the min is greater than max */    
        } elseif ($this->settings['minChar'] > $this->settings['maxChar']) {
            
            /** set $numChar to smaller (maxChar) */
            $numChar = $this->settings['maxChar'];
        }
        
        /** if $numChar is bigger than abs max or smaller then absmin change it respectivly */
        if ($numChar > $this->absMax) { $numChar = $this->absMax; } else if ($numChar < $this->absMin) { $numChar = $this->absMin; }
        
        /** reset the tmpPassword */
        $tmpPass = '';
        
        /** loop for the number of characters needed for password */
        for ($n = 0; $n <= $numChar; $n++) {
            /** add another character to the end of the password string */
            $tmpPass .= $this->_getChar($ok[array_rand($ok)]);
        }
        
        /** add password to the $this->passwords array */
        $this->password[] = $tmpPass;
        
        /** clear the temp password */
        $tmpPass = '';
    }
    
    /** after all passwords have been generated return the password array */
    return $this->password;
  }

  
  /** ****************
  * Added: 3.0
  * Description: used to get settings due to settings being a private variable 
  **************** */
  public function getSettings() { return $this->settings; }
  
  /** ****************
    * Added: 4.0
    * Description: will return a string in json format for all of the passwords requested; great for passing to other languages 
    * Example:
    * $pw->jsonPasswords($settings) //settings can be passed durring the function call
    * *output*: {"0" : "posdfihjasdhn"};
    **************** */
  public function jsonPasswords($s) { return is_null($this->password) ? json_encode($this->genPass($s)) : json_encode($this->password); }
  
  /** ****************
  * Added: 3.0
  * Description: Used to convert any letter letter into a "l33t" letter; 
  * Example:
  * $pw->l33tLetter('s');
  * *output* $
  **************** */
  public function l33tLetter($org) {
    
    /** check if string is 1 character in length and that it is really a string */
    /** if it is a valid string convert it to lowercase to make sure it is compatible with array */
    if (!is_string($org) || strlen($org) > 1) { return false; } else { $org = strtolower($org); }
    
    /** conversion array */
    $l33tArray = array(
      "a" => array("4", "@", "/ - \\", "/\\", "^", "aye"),
      "b" => array("8", "|3", "6", "13", "]3", "ß"),
      "c" => array("(", "<", "¢", "{", "©", "sea", "see"),
      "d" => array("|)", "[)", "?", "I>", "|>"),
      "e" => array("3", "£", "&", "€", "[-", "?"),
      "f" => array("|=", "]=", "}", "ph", "(=", "?"),
      "g" => array("6", "&", "(_+", "C-", "gee", "jee", "(Y,"),
      "h" => array("#", "|-|", "]-[", "[-]", ")-(", "(-)", ":-:", "}{", "aych"),
      "i" => array("!", "1", "|", "eye", "3y3", "ai", "¡"),
      "j" => array("_|", "_/", "]", "¿", "</", "_)", "?"),
      "k" => array("|<", "|{"),
      "l" => array("1", "7", "|_", "£", "|"),
      "m" => array("44", "/\\/\\", "|\\/|", "em", "|v|", "IYI", "IVI", "[V]", "^^", "nn"),
      "n" => array("|\|", "?", "[\]", "<\>", "{\}"),
      "o" => array("0", "()", "oh", "[]", "O"),
      "p" => array("|*", "|º", "|>", "|\"", "9", "?", "þ", "|D"),
      "q" => array("9", "0_", "0,", "(,)", "<|", "cue", "¶"),
      "r" => array("|2", "/2", "I2", "|^", "|~", "?"),
      "s" => array("$", "5", "z", "§", "es"),
      "t" => array("+", "7", "-|-", "†"),
      "u" => array("|_|", "(_)", "[_]", "{_}", "\_/"),
      "v" => array("\/", "v"),
      "w" => array("\/\/", "vv", "\^/", "(n)", "\X/", "\|/", "UU"),
      "x" => array("%", "><", "}{", "ecks", ")(", "ex"),
      "y" => array("`/", "`(", "-/", "?", "?", "¥"),
      "z" => array("2", "=", "~/_", "7_"));
      
    /** return a random element in the array for that letter */
    return $l33tArray[$org][array_rand($l33tArray[$org])];
  }

  /** ****************
  * Added: 3.0
  * Description: Will convert a normal string into a more secure string by switching numbers/letters with symiler numbers/symbols 
  * Example:
  * $pw->makeSecure('Hello World!')
  * *Output*: |-|317o vv0/2|_d!
  **************** */
  public function makeSecure($word) {
    
    /** end function if avariable passed is not a string or is empty */
    if (!is_string($word) || is_null($word)) { return false; }
    
    /** Set Variables */
    $secureWord = "";
    $letterLower = array("l33tLetter", "toUpper", "nothin");
    $letterUpper = array("l33tLetter", "toLower", "nothin");
    $numberF = array("numToLetter", "numToSpecs", "nothin");
    
    /** Loop through letters in string */
    for ($i = 0; $i < strlen($word); $i++) {
      /** Get character from word */
      $l = substr($word, $i, 1);
      
      /** Set $functions to array based on type of character or nothin if it is a special character */
      $functions = (ctype_lower($l) ? $letterLower : (ctype_upper($l) ? $letterUpper : (ctype_digit($l) ? $numberF : array('nothin'))));
      
      /** get a random function from the array of functions, call function and add returned value to end of $secureWord to be returned */
      $secureWord .= call_user_func("self::" . $functions[array_rand($functions)], $l);
    }
    
    /** Return the generated $secureWord */
    return $secureWord;
  }
  
  /** ****************
  * Added: 1.0
  * Description: allows settings to be changed, but only the specified settings
  * Example:
  * $pw->settings(array('minChar' => 40)); //set the minimum length to 40
  **************** */
  public function settings($param = array()) {
    
    /** if $param isn't an array or is empty then the function will return false */
    if (empty($param) || gettype($param) != 'array') { return false; }
    
    /** Check each setting and if it is passed in the $param then set it - otherwise make no changes */
    $this->settings['minChar'] = array_key_exists('minChar', $param) && is_numeric($param['minChar']) ? ($param['minChar'] > $this->absMin ? $this->absMin : $param['minChar']) : $this->settings['minChar'];
    $this->settings['maxChar'] = array_key_exists('maxChar', $param) && is_numeric($param['maxChar']) ? ($param['maxChar'] > $this->absMax ? $this->absMax : $param['maxChar']) : $this->settings['maxChar'];
    
    if (array_key_exists('req', $param) && is_array($param['req'])) {
        $this->settings['req'] = array_merge($this->settings['req'], $param['req']);
    }
    $this->settings['upper'] = array_key_exists('upper', $param) && is_string($param['upper']) ? $param['upper'] : $this->settings['upper'];
    $this->settings['lower'] = array_key_exists('lower', $param) && is_string($param['lower']) ? $param['lower'] : $this->settings['lower'];
    $this->settings['num'] = array_key_exists('num', $param) && is_string($param['num']) ? $param['num'] : $this->settings['num'];
    $this->settings['specs'] = array_key_exists('specs', $param) && is_string($param['specs']) ? $param['specs'] : $this->settings['specs'];
    $this->settings['disallowed'] = array_key_exists('disallowed', $param) && is_string($param['disallowed']) ? $param['disallowed'] : $this->settings['disallowed'];
    $this->settings['numPasswords'] = array_key_exists('numPasswords', $param) && is_string($param['numPasswords']) ? $param['numPasswords'] : $this->settings['numPasswords'];
  }
  
  /** ****************
  * Added: 4.0
  * Description: get a single password returned in a string; will return the numPasswords to org. value; settings can be passed to array
  * Example:
  * $pw->singlePassword();
  * *output*: kdjfnasdfn
  **************** */
  public function singlePassword($settings = array()) {
    if (gettype($this->password) != 'array' || empty($this->password)) {
	  /** get org value of numPasswords */
	  $curNum = $this->settings['numPasswords'];

	  /** set settings if they have been passed */
	  (!empty($settings) && gettype($settings) == 'array' ? $this->settings($settings) : null);

	  /** change number passwords to 1 */
	  $this->settings(array('numPasswords' => 1));

	  /** generate password */
	  $this->password = $this->genPass();
		
	  /** reset settings back to current NumPasswords */
	  $this->settings(array('numPasswords' => $curNum));
    }
      
	  /** return password */
	  return $this->password[0];
  }

  
  /** ****************
  * Added: 3.0
  * Description: will return a security level for the string passed; 0-100 scale 
  * Example:
  * $pw->strength('password1') = ~26;
  **************** */
  public function strength($pass) {
    
    /** trim password to make sure there are no extra spaces */
    $pass = str_replace(" ", "", trim($pass));
    
    /** check to make sure that password is a string and isn't empty */
    if (!is_string($pass) || empty($pass) ) { return false; }
    
    /** password length */
    $password_length = strlen($pass);
    
    /** Final score for password */
    $finalScore = 0;
    
    /** a-z characters string */
    $characters = "abcdefghijklmnopqrstuvwxyz";
    
    /** generic numbers string */
    $numbers = "0123456789";
    
    /** Specs variable */
    $specs = "!@#$%^&*()";
    
    /** minimum length for fully secure password */
    $minimum_length = 8;
    
    /** multiplyer for special characters */
    $multi_specs = 6;
    
    /** multiplyers with value of 4 */
    /** length and numbers */
    $multi_length = $multi_number = 4;
    
    /** multiplyer for sequental characters */
    $multi_sequental_letters = $multi_sequental_numbers = $multi_sequental_specs = 3;
    
    /** multipler for repeated characters and numbers/specs in the middle of password */
    $multi_middle_chars = $multi_repeat_uppers = $multi_repeat_lowers = $multi_repeat_nums = 2;
    
    /** counters */
    $middle_num_specs = $count_uppers = $repeating_uppers = $count_lowers = $repeating_lowers = $count_nums = $repeating_nums = $count_specs =
    $repeating_char_increment = $repeating_char = $count_unique_char = $count_required = $count_sequental_letters = $count_sequental_nums = $count_sequental_specs = 0;
    
    $prev_upper = $prev_lower = $prev_num = -1;
    
    /** Set initail score length * multipler (4) */
    $finalScore = $password_length * $multi_length;
    
    /** loop through all characters in password */
    for ($l = 0; $l < $password_length; $l++) {
        
        /** get current character */
      $curChar = substr($pass, $l, 1);
      
        /** check if character is upper */
        if (ctype_upper($curChar))  {
            /** if the last character was uppercase letter then add 1 to $repeating uppercase variable*/
            if (($prev_upper + 1) == $l && $prev_upper > 0) { $repeating_uppers++; }
            
            /** set $l to $prev_upper and $count_uppers (number of uppercase letters)  */
            $prev_upper = $l;
            $count_uppers++;
        } else if (ctype_lower($curChar)) {
            
            /** if there is a lowercase letter check for repeating lowercase letters */
            if (($prev_lower + 1) == $l && $prev_lower > 0) { $repeating_lowers++; }
            
            /** set temp lower to current letter and add 1 to lower count */
            $prev_lower = $l;
            $count_lowers++;
        } else if (ctype_digit($curChar)) {
            
            /** if the number is in the middle of the password then add one to middle number */
            if ($l > 0 && $l < ($password_length - 1)) { $middle_num_specs++; }
            
            /** if previous character was a number then add to repeating numbers */
            if ($prev_num > 0 && ($prev_num + 1) == $l) { $repeating_nums++; } 
            
            /** set current number and add one to count of numbers */
            $prev_num = $l;
            $count_nums++;
        } else if (!ctype_alnum($curChar)) {
            
            /** if character is a middle character then add to middle numbers */
            if ($l > 0 && $l < ($password_length - 1)) { $middle_num_specs++; }
            
            /** add to count special characters */
            $count_specs++;
        }
        
      /** reset dup char variable */
      $dupChar = false;
      
      /** loop through password and check for duplicate characters */
      for ($i = 0; $i < $password_length; $i++) {
        
        /** if there is a duplicate characters */
        if ($curChar == substr($pass, $i, 1) && $l != $i) {
            
            /** set dupChar to true */
            $dupChar = true;
            
            /** add to repeating character incrmeent */
            $repeating_char_increment += abs($password_length / ($i - $l));
        }
      }
      
      /** if there are dup characters */
      if ($dupChar) {
        
        /** add to repeating characters */
        $repeating_char++;
        
        /** get number of unique characters */
        $count_unique_char = $password_length - $repeating_char;
        
        /** devide by number of unique characters and round up */
        $repeating_char_increment = ($count_unique_char) ? ceil($repeating_char_increment / $count_unique_char) : ceil($repeating_char_increment);
      }
    } /** end of loop through each character in password */
    
    
    /** loop through password and see if there are any sequental characters */
    for ($c = 0;$c <= strlen($pass) - 3; $c++) {
        
        /** get current 3 letters in password forward and reverse */
        $forward = substr(strtolower($pass), $c, 3);
        $reverse = strrev($forward);
        
        /** check for squental characters (numbers, letters, and specs) */
        if (strpos($characters, $forward) !== false || strpos($characters, $reverse) !== false) { $count_sequental_letters++; }
        if (strpos($numbers, $forward) !== false || strpos($numbers, $reverse) !== false) { $count_sequental_nums++; }
        if (strpos($specs, $forward) !== false || strpos($specs, $reverse) !== false) { $count_sequental_specs++; }
    }
    
    /** add/subtract from final score based on several factors */
    $finalScore += $count_uppers > 0 && $count_uppers < $password_length ? $password_length - $count_uppers * 2 : 0;
    $finalScore += $count_lowers > 0 && $count_lowers < $password_length ? $password_length - $count_lowers * 2 : 0;
    $finalScore += $count_nums > 0 && $count_nums < $password_length ? $count_nums * $multi_number : 0;
    $finalScore += $count_specs > 0 ? $count_specs * $multi_specs : 0;
    $finalScore += $middle_num_specs > 0 ? $middle_num_specs * $multi_middle_chars : 0;
    $finalScore -= ($count_uppers > 0 || $count_lowers > 0) && $count_specs == 0 && $count_nums == 0 ? $password_length : 0;
    $finalScore -= $count_uppers == 0 && $count_lowers == 0 && $count_specs == 0 && $count_nums > 0 ? $password_length : 0;
    $finalScore -= $repeating_char > 0 ? $repeating_char_increment : 0;
    $finalScore -= $repeating_uppers > 0 ? $repeating_uppers * $multi_repeat_uppers : 0;
    $finalScore -= $repeating_lowers > 0 ? $repeating_lowers * $multi_repeat_lowers : 0;
    $finalScore -= $repeating_nums > 0 ? $repeating_nums * $multi_repeat_nums : 0;
    $finalScore -= $count_sequental_letters > 0 ? $count_sequental_letters * $multi_sequental_letters : 0;
    $finalScore -= $count_sequental_nums > 0 ? $count_sequental_nums * $multi_sequental_numbers : 0;
    $finalScore -= $count_sequental_specs > 0 ? $count_sequental_specs * $multi_sequental_specs : 0;
    
    /** check for the required features of password (length, uppers, lowers, numbers, specs) */
    $count_required += $password_length >= $minimum_length ? 1 : 0;
    $count_required += $count_uppers > 0 ? 1 : 0;
    $count_required += $count_lowers > 0 ? 1 : 0;
    $count_required += $count_nums > 0 ? 1 : 0;
    $count_required += $count_specs > 0 ? 1 : 0;
    
    /** add points for meeting specified number of requirements */
    $finalScore += ($password_length >= $minimum_length && $count_required > 3) || ($count_required >= 4 && $password_length < $minimum_length) ? $count_required * 2 : 0;
    
    /** return the final score */
    return $finalScore > 100 ? 100 : $finalScore < 0 ? 0 : $finalScore;
  }
  
  /** ****************
  * Added: 3.0
  * Description: Validate password entered w/ encrypted text passed;
  *              if $hash and $salt aren't set then they will need to be passed to the function
  * Example:
  * $pw->validPassword('123456', 'ldasfklasndfklnasdfkl', 'md5', date());
  * *Output*: false
  **************** */
  public function validPassword($pass, $cypherText, $hash = '', $salt = '') {
    
    /** trim password or set to an empty string if password isn't a string */
    $pass = (is_string($pass) ? trim($pass) : '');
    
    /** trim $cyphertext or set it to an empty string if it isn't a string */
    $cypherText = (is_string($cypherText) ? trim($cypherText) : '');
    
    /** return false if password or cyphertext is empty */
    if (empty($pass) || empty($cypherText)) { return false; }
    
    /** return true or false if the cyphertext passed matches the password passed and encypted */
    return ($cypherText == $this->encrypt($pass, $hash, $salt));
  }
  
  /**
   * END Password functions --------------------------------------------------------------------------------------------------------------
  */
  
  /**
   * Encryption functions --------------------------------------------------------------------------------------------------------------
  */
  
  /** ****************
  * Added: 3.0
  * Description: used to encrypt a string with the provided $hash and $salt 
  * Example:
  * $pw->encrtpt('123456', 'sha1', date());
  * 
  **************** */
  public function encrypt($pw, $hash = '', $salt = '') {
    /** Trim any extra spaces at the front and end of $pw */
    $pw = trim($pw);
    /** Trim String and set to empty string if something other than a string is passed to $salt */
    $salt = (is_string($salt) ? trim($salt) : '');
    
    /** Trim String and set to empty string if something other than a string is passed to $salt */
    $hash = (is_string($hash) ? trim($hash) : '');
    
    /** $r is a return checking variable, if set to true it will cause function to return before encrypting */
    $r = false;
    
    /** Return False if $pw isn't a string or is empty */
    if (!is_string($pw) || $pw == '') { return "Invalid Password"; }
    
    /** Set hash if passed and valid */
    if (!empty($hash) && $this->validHash($hash)) { $this->setHash($hash); };
    
    /** if hash is valid then set it as the hash type else set $r to true causing function to stop when checked */
    (empty($this->hashType)) ? $r = "Empty Hash" : (!$this->validHash($this->hashType)) ? $r = "Invalid Hash" : null;
    
    /** if $salt is provided then set $salt variable; variable doesn't have to be set so null is else */
    (!empty($salt) ? $this->setSalt($salt) : null);
    
    /** End function if $r is set to true  */
    if ($r !== false) { return $r; }
    
    /** Encrypt the password and set it to the cyphertext variable */
    $this->cypherText = hash($this->hashType, $pw . $this->getSalt());
    
    /** return the cyphertext variable */
    return $this->cypherText;
  }
  
  /** ****************
  * Added: 3.0
  * Description: Used to get all available hash's (encryption types... sha1, md5, blow); will return array of hash's 
  **************** */
  public function getHashes() { return hash_algos(); }

  /** ****************
  * Added: 3.0
  * Description: Used to get currently set salt 
  **************** */
  public function getSalt() { return $this->salt; }

  
  /** ****************
  * Added: 3.0
  * Description: used to set the hash (or encryption) type; 
  * Example:
  * $pw->setHash('md5');
  **************** */
  public function setHash($type) { if (empty($type) || gettype($type) != 'string') { return false; } $this->hashType = trim($type); }
  
  /** ****************
  * Added: 3.0
  * Description: used to set the "salt" peramiter when encrypting a password
  * Example:
  * $pw->setSalt('mySalttext')
  **************** */
  public function setSalt($salt) { if (!empty($salt) && gettype($salt) == 'string') { $this->salt = trim($salt); } else { return false; } }
  
  /** ****************
  * Added: 3.0
  * Description: Check if the htype passed is a valid hash on the server; if no hash is passed then function will return false 
  * Example: 
  * $pw->validHash('md5');
  * *output*: true
  **************** */
  public function validHash($hType = '') {
    
    /** check if $htype is set and is a string; trim it if it is a valid string */
    return (empty($hType) || gettype($hType) != 'string') ? false : in_array(trim($hType), $this->getHashes());
  }
  
  /**
   * END Encryption functions --------------------------------------------------------------------------------------------------------------
  */
  
  
  /**
   * Other functions --------------------------------------------------------------------------------------------------------------
  */
  
  /** ****************
  * Added: 4.0
  * Description: Used to add a phonetic catigory; 
  * Example:
  * $pw->addPhonetic(array('a' => 'anteater'), 'anamals')
  **************** */
  public function addPhonetic($arr, $title = '') {
    if (!empty($title) && gettype($title) == 'string') {
        if (!array_key_exists($title, $this->phoneticArr)) {
            $this->phoneticArr[$title] = array();
        }
        $this->phoneticArr[$title] = array_merge($this->phoneticArr[$title], $arr);
    }
  }
  
  /** ****************
  * Added: 4.0
  * Description: Used to add a phonetic type to the $phoneticArr used to convert characters to words
  * Example:
  * $pw->addType(array('anamals' => array('a' => 'anteater')))
  **************** */
  public function addType($config = array()) {
    /** end function if $config isn't passed or if it isn't an array */
    if (empty($config) || !is_array($config)) {
      return;
    }

    /** Loop through each entry in $config */
    foreach ($config as $k => $v) {
        
      /** If $v is an array and $k isn't already in the $this->types array then add it in */
      /** This will prevent any of the default options from being overwriten */
      if (is_array($v) && !in_array($k, $this->types)) {
        $this->types[$k] = $v;
      } else if (!in_array($k, $this->types)) {
        $this->types[$k] = array();
      }
    }
  }
  
  /** ****************
  * Added: 4.0
  * Description: returns current version of passWord class 
  * Example: $pw->curVer = 4.0;
  **************** */
  public function curVer() { return self::TITLE . ' v' . self::VERSION; }
  
  
  /** ****************
  * Added: 4.0
  * Description: Will return associatve array with info about each password
  * Example:
  **************** */
  public function info($pw) {
    if (gettype($pw) == 'string') {
        $pw = array($pw);
    } else if (gettype($pw) != 'array') {
        return false;
    }
    
    $returnArray = array();
    $tmpArray = array();
    foreach ($pw as $password) {
      $tmpArray['password'] = trim($password);
      $tmpArray['upper'] = strlen(preg_replace('![^A-Z]+!', '', $password));
      $tmpArray['lower'] = strlen(preg_replace('![^a-z]+!', '', $password));
      $tmpArray['num'] = strlen(preg_replace('![^0-9]+!', '', $password));
      $tmpArray['specs'] = strlen(preg_replace('![0-9a-zA-Z]+!', '', $password));
      $tmpArray['time2Crack'] = $this->time2Crack($password);
      $tmpArray['strength'] = $this->strength($password);
      $returnArray[] = $tmpArray;
      $tmpArray = array();
    }
    
    return $returnArray;
  }
  
  /** ****************
  * Added: 3.0
  * Description: Returns the item passed; used as a default function in the makeSecure function  
  **************** */
  public function nothin($l) { return $l; }
  
  /** ****************
  * Added: 3.0
  * Description:  Will convert a number to a letter caps unless othersize specified
  * Example:
  * $pw->numToLetter(4, false) - $pw->numToLetter(4)
  * *OUTPUT*: a - A
  **************** */
  public function numToLetter($num, $caps = true) {
    
    /** Make sure that the number passed is a real number between 0 and 9 */
    if (strcspn($num, '0123456789') == strlen($num) || intval($num) > 9 || intval($num) < 0) {
      return false;
    }
    
    /** Replacement array */
    $num2L = array('O', 'I', 'Z', 'E', 'A', 'S', 'G', 'T', 'B', 'G');
    
    /** Return a capitol letter or a lowercase letter */
    return ($caps ? $num2L[intval($num)] : strtolower($num2L[intval($num)]));
  }
  
  /** ****************
  * Added: v3.0
  * Description: Will convert a nubmer to a special character; Will also omit any text in string and return false if no numbers are passed  
  * Example: 
  * echo $pw->numToSpecs(3three);
  * *OUTPUT*: #
  **************** */
  public function numToSpecs($num) {
    /** Returns false if a number above 9 is passed or string doesn't contain numbers */
    if (strcspn($num, '0123456789') == strlen($num) || intval($num) > 9 || intval($num) < 0) { return false; }
    
    /** replacement array */
    $num2S = array(')', '!', '@', '#', '$', '%', '^', '&', '*', '(');
    
    /** Return item $num in replacement array */
    return $num2S[intval($num)];
  }
  
  /** ****************
  * Added: 4.0
  * Description: Used to convert a word or password ($pw) to a phoneic output; anycharacters not supported with be checked to see if there is a "normal"
  *              version or returned as is
  * Example:
  * echo $pw->phonetic('W3st;C0st', 'military', ' - ');
  * *Output*: WHISKEY - THREE - sierra - tango - ; - CHARLIE - ZERO - SIERRA - tango 
  **************** */
  public function phonetic($pw, $format = 'normal', $glue = ' ') {
     
    /** If $pw isn't a string then the function will return $pw */
    if (gettype($pw) != 'string') { return $pw; }
    
    /** Replace glue if string not passed */
    $glue = (gettype($glue) != 'string' ? ' ' : $glue);
     
    /** replace any characters not allowed with normalized versions */
    $pw = $this->_normalize($pw);
    
    /** change format to normal if format passed isn't valid */
    $format = (array_key_exists($format, $this->phoneticArr) ? $format : 'normal');
    
    /** Reset Variables used in function */
    $outputArr = array();
    $tmpOutput = '';
    
    /** loop through $pw string */
    for ($l = 0; $l <strlen($pw); $l++){
        
        /** Get Current Letter */
        $letter = $pw[$l];
        
        /** Convert to lower to search through arrays */
        $ltr = strtolower($letter);
        
        /** get phonetic version of character */
        $tmpOutput = !array_key_exists($ltr, $this->phoneticArr[$format]) ? (!array_key_exists($ltr, $this->phoneticArr['normal']) ? $letter : $this->phoneticArr['normal'][$ltr]) : 
        (is_array($this->phoneticArr[$format][$ltr]) ? $this->phoneticArr[$format][$ltr][array_rand($this->phoneticArr[$format][$ltr], 1)] : $this->phoneticArr[$format][$ltr]);
        
        /** Upercase phonetic version if the letter was upercase or lowercase and add to $outputArr */
        $outputArr[] = (ctype_upper($letter) || ctype_digit($letter)) ? strtoupper($tmpOutput) : strtolower($tmpOutput);
    }
    
    /** convert array to string and add $glue between words */
    return implode($glue, $outputArr);
  }

  
  /** ****************
  * Added: 3.0
  * Description: Will generate a string with random words selected from alphabetical files stored on the server;
  *              all a words should be in the 'words' folder in a file called a.txt
  *              folder location can be changed with the $folder varialbe
  *              words will also be filtered by min and max number of letters
  * Example:
  * $pw->randomWords(4, 9, 12, '_')
  * *output*: generator_caponized_quaveringly_amylopectins
  **************** */
  public function randomWords($numWords, $minLetters = 4, $maxLetters = 7, $glue = ' ', $folder = "") {
    
    /** reset the array of words */
    $final_word_string = array();
    
    /** set the number of words to be generated (3 min 10 max) */
    $numWords = (!is_numeric($numWords) || empty($numWords) || $numWords <= 2) ? 3 : ($numWords > 15 ? 15 : $numWords);
    
    /** set the min number of letters in the word if number is less that 1 the reset val to 6 */
    $minLetters = (!is_numeric($minLetters) || $minLetters < 3) ? 3 : $minLetters;
    
    /** set the max number of letters - max of 50 */
    $maxLetters = (!is_numeric($maxLetters) || $maxLetters > 20) ? 20 : $maxLetters;
    
    /** change folder of (a.txt, b.txt, c.txt,... ect) files; default of words */
    $folder = (!empty($folder) && is_string($folder) ? $folder . "/" : "words/");
    
    /** set string of acceptable letters that words can start with (i.e. file names) */
    $letters = "abcdefghijklmnopqrstuvwxyz";
    
    /** file extention */
    $ext = ".txt";
    
    /** Set the limit for the number of times a character can be searched for */
    $loopLimit = $numWords * 5;
    
    /** Raw Loop counter - keep track of the number of times the loop has been run */
    $curLoop = 0;
    
    /** loop through number of words to be generated */
    for ($c = 0; $c < $numWords; $c++) {
        /** get random letter to generate word from */
      $letter = substr($letters, rand(0, strlen($letters)-1), 1);
      
      /** get file location of words to be generated */
      $file = $folder . $letter . $ext;
      
      /** check if file exists */
      if (file_exists($file)) {
        
        /** get all words in file - array format */
        $wordArr = file($file);
        
        /** get a random word from the array */
        $word = $wordArr[array_rand($wordArr, 1)];
        
        /** check if word matches specified format */
        if (strlen($word) > $maxLetters || strlen($word) < $minLetters) {
            /** if it doesn't then lower loop count to try again */
          $c--;
          
        } else {
            
            /** if word matches then added it to final word array */
          $final_word_string[] = $word;
        }
      } else {
        
        /** if file doesn't exsts then lower loop count to try again */
        $c--;
      }
        /** check raw loop limit */
        if ($curLoop == $loopLimit) {
            
            /** if loop limit has been reached then end for loop even if number of words requested hasn't been reached */
            break;
        } else {
            
            /** if loop limit hasn't been reached then add one to the loop counter */
            $curLoop++;
        }
    }
    
    /** return the words array and join it with the glue provided */
    return join($glue, $final_word_string);
  }
  
  /** ****************
  * Added: 4.0
  * Description: converts raw secongs to year,month,week,day,hour,min,sec output 
  * Example:
  * sec2time(31536000) = 1 year
  **************** */
  public function sec2time($sec) {
        $sec_in_year = 31536000; 
        $sec_in_month = 2628000; 
        $sec_in_week = 604800;
        $sec_in_day = 86400;
        $sec_in_hour = 3600;
        $sec_in_min = 60;
        
        
        $units = array('year', 'month', 'week', 'day', 'hour', 'min', 'sec');
        $remainder = $sec;
        $string = '';
        for ($c = 0;$c <= count($units);$c++) {
            switch ($units[$c]) {
               case 'year':
                if ($remainder >= $sec_in_year) {
                    $years = floor($sec / $sec_in_year);
                    $remainder -= $years*$sec_in_year;
                    $string .= $years . ' Year' . ($years > 1 ? 's ' : ' ');
                }
               break;
               case 'month':
                if ($remainder >= $sec_in_month) {
                    $months = floor($remainder / $sec_in_month);
                    $remainder -= $months*$sec_in_month;
                    $string .= $months . ' Month' . ($months > 1 ? 's ' : ' ');
                }
               break;
               case 'week':
                if ($remainder >= $sec_in_week) {
                    $weeks = floor($remainder / $sec_in_week);
                    $remainder -= $weeks*$sec_in_week;
                    $string .= $weeks . ' Week' . ($weeks > 1 ? 's ' : ' ');
                }
               break;
               case 'day':
                if ($remainder >= $sec_in_day) {
                    $days = floor($remainder / $sec_in_day);
                    $remainder -= $days*$sec_in_day;
                    $string .= $days . ' Day' . ($days > 1 ? 's ' : ' ');
                }
               break;
               case 'hour':
                if ($remainder >= $sec_in_hour) {
                    $hour = floor($remainder / $sec_in_hour);
                    $remainder -= $hour*$sec_in_hour;
                    $string .= $hour . ' Hour' . ($hour > 1 ? 's ' : ' ');
                }
               break;
               case 'min':
                if ($remainder >= $sec_in_min) {
                    $minute = floor($remainder / $sec_in_min);
                    $remainder -= $minute*$sec_in_min;
                    $string .= $minute . ' Minute' . ($minute > 1 ? 's ' : ' ');
                }
               break;
               case 'sec':
                if ($remainder > 0) {
                    $seconds = floor($remainder);
                    $remainder -= $seconds;
                    $string .= $seconds . ($remainder > 0 ? ltrim($remainder, '0') : '') . ' Second' . ($seconds > 1 ? 's ' : ' ');
                }
               break;
            }
        }
        
        return $string;
    }
  /** ****************
    * Added: 4.0
    * Description: function should return the length of time needed to crack the password using a brute force attack;
    * Input: 
    * $pw = password;
    * $gps = number of guesses per second
    *  
    * Example:
    **************** */
    public function time2Crack($pw, $gps = 4000000000) {
         
         /** declare variables */
         $password_length = 0;
         $possible_characters = 0;
         $number_combonations = 0;
         $time2Crack = 0;
         
         $character_types = array(
           array('type' => 'ASCII Lowercase', 'pattern' => '/[a-z]/', 'characters' => 26),
           array('type' => 'ASCII Uppercase', 'pattern' => '/[A-Z]/', 'characters' => 26),
           array('type' => 'ASCII Numbers', 'pattern' => '/\d/', 'characters' => 10),
      	   array('type' => 'ASCII Top Row Symbols', 'pattern' => '/[!@£#\$%\^&\*\(\)\-_=\+]/', 'characters' => 15),
        	 array('type' => 'ASCII Other Symbols', 'pattern' => '/[\?\/\.>\,<`~\\|"\';:\]\}\[\{\s]/', 'characters' => 19),
        	 array('type' => 'Unicode Latin 1 Supplement', 'pattern' => '/[\u00A1-\u00FF]/', 'characters' => 94),
        	 array('type' => 'Unicode Latin Extended A', 'pattern' => '/[\u0100-\u017F]/', 'characters' => 128),
      	   array('type' => 'Unicode Latin Extended B', 'pattern' => '/[\u0180-\u024F]/', 'characters' => 208),
      	   array('type' => 'Unicode Latin Extended C', 'pattern' => '/[\u2C60-\u2C7F]/', 'characters' => 32),
        	 array('type' => 'Unicode Latin Extended D', 'pattern' => '/[\uA720-\uA7FF]/', 'characters' => 29),
        	 array('type' => 'Unicode Cyrillic Uppercase', 'pattern' => '/[\u0410-\u042F]/', 'characters' => 32),
        	 array('type' => 'Unicode Cyrillic Lowercase', 'pattern' => '/[\u0430-\u044F]/', 'characters' => 32)
         );
         
         /** Check input variables first */
         if (gettype($pw) != 'string' || empty($pw) || !is_numeric($gps) || $gps <= 0) {
            return false;
         }
         
         /** make sure that password isn't one of the most common passwords */
         if (in_array($pw, $this->commonPasswords)) {
           return 'Instantly';
         }
         
         /** get password length */
         $password_length = strlen($pw);
         
         /** loop through possible character types and see if they are presnt in the password - if so, then add them to the possible character count */
         foreach ($character_types as $type) {
            /** check if pattern $type['pattern'] matches password */
            /** if it does match then add $type['characters'] to $possible_characters */
            /** might use teriny $possible_characters += (preg.match) ? $type['characters'] : 0; */
            
            if (preg_match($type['pattern'], $pw)) {
            	$possible_characters += $type['characters'];
            }
         }
         
         /** get the number of possible combonations */
         $number_combonations = gmp_strval(gmp_pow($possible_characters, $password_length));
         
         /** divide number of possible combos by number of guesses per second to get number of seconds to go through all possible passwords */
         $time2Crack = $number_combonations / $gps;
         
         /** convert to normal output: 1 hour 35 min 20.245 seconds */
         return $this->sec2time($time2Crack) . ' at ' . $gps;
    }
  
  /** ****************
  * Added: 4.0
  * Description: Convert number (1,234,567) to (1 Million 2 Hundred 34 thousand 5 Hundred and 67) 
  * Example:
  **************** */
  //TODO: Finish Function - possible switch/loop like on sec2time - http://bmanolov.free.fr/numbers_names.php - Use associative array of us/uk/de versions
  
  public function largeNumbers($number) {
    
  }
  
  /** ****************
  * Added: 3.0
  * Description: Will return a lowercase letter; will return false if string passed is more than one character in length or not a string;
  * Example:
  * $pw->toLower('R')
  * *output*: r
  **************** */
  public function toLower($letter) { if (!ctype_upper($letter) || strlen($letter) != 1) { return false; } else { return strtolower($letter); } }
  
  /** ****************
  * Added: 3.0
  * Description: will convert a lowercase letter to upper; 
  * Example:
  * $pw->toUpper('t');
  * *output*: T
  **************** */
  public function toUpper($letter) { return (!ctype_lower($letter) || strlen($letter) != 1) ? false : strtoupper($letter); }
  
  /**
   * END Other functions --------------------------------------------------------------------------------------------------------------
  */
}
?>
