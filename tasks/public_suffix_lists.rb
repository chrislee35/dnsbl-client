# frozen_string_literal: true

# Builds data/two-level-tlds and data/three-level-tlds from the Public Suffix List (https://publicsuffix.org/).
#
# The lists hold the suffixes that have two and three labels (co.uk, k12.ca.us). A rule that starts with a wildcard ("*.ck", meaning every
# name one label below ck is a suffix) is kept in the list of its own length, and so is an exception ("!www.ck", registrable even though the
# wildcard would make it a suffix). Rules with four or more labels do not fit these lists and are left out. Internationalized labels are
# converted to punycode, because they are what appears in DNS queries.
module PublicSuffixLists
  URL = 'https://publicsuffix.org/list/public_suffix_list.dat'
  LENGTHS = { 2 => 'two-level-tlds', 3 => 'three-level-tlds' }.freeze

  # RFC 3492 parameters
  BASE = 36
  TMIN = 1
  TMAX = 26
  SKEW = 38
  DAMP = 700
  INITIAL_BIAS = 72
  INITIAL_N = 128

  Result = Struct.new :lists, :skipped, :version, :commit

  module_function

  # parses the text of a Public Suffix List and returns a Result: lists maps 2 and 3 to sorted arrays of rules,
  # skipped counts the rules that were left out by label count
  def parse(text)
    lists = LENGTHS.keys.to_h { |length| [length, []] }
    skipped = Hash.new 0
    text.each_line do |line|
      rule = line.strip.split.first
      next if rule.nil? || rule.start_with?('//')

      prefix = rule.start_with?('!') ? '!' : ''
      labels = rule.delete_prefix('!').downcase.split('.').map { |label| to_ascii label }
      if lists.key? labels.length
        lists[labels.length] << "#{prefix}#{labels.join '.'}"
      else
        skipped[labels.length] += 1
      end
    end
    lists.each_value do |rules|
      rules.uniq!
      rules.sort!
    end
    Result.new lists, skipped, text[%r{^// VERSION: (.+)$}, 1], text[%r{^// COMMIT: (.+)$}, 1]
  end

  # writes the lists into directory, one rule per line
  def write(result, directory)
    LENGTHS.each do |length, name|
      File.write File.join(directory, name), result.lists[length].map { |rule| "#{rule}\n" }.join
    end
  end

  # converts a label to its ASCII form: xn-- and punycode if it has non-ASCII characters, otherwise unchanged
  def to_ascii(label)
    label.ascii_only? ? label : "xn--#{punycode label.unicode_normalize(:nfc)}"
  end

  # RFC 3492 punycode encoding of a string
  def punycode(input)
    codepoints = input.codepoints
    output = codepoints.filter_map { |c| c.chr if c < INITIAL_N }
    basic = handled = output.length
    output << '-' if basic.positive?
    n = INITIAL_N
    delta = 0
    bias = INITIAL_BIAS
    while handled < codepoints.length
      m = codepoints.select { |c| c >= n }.min
      delta += (m - n) * (handled + 1)
      n = m
      codepoints.each do |c|
        delta += 1 if c < n
        next unless c == n

        output << encode_integer(delta, bias)
        bias = adapt delta, handled + 1, handled == basic
        delta = 0
        handled += 1
      end
      delta += 1
      n += 1
    end
    output.join
  end

  # encodes delta as a generalized variable-length integer
  def encode_integer(delta, bias)
    digits = []
    q = delta
    k = BASE
    loop do
      t = if k <= bias
            TMIN
          else
            k >= bias + TMAX ? TMAX : k - bias
          end
      break if q < t

      digits << digit(t + ((q - t) % (BASE - t)))
      q = (q - t) / (BASE - t)
      k += BASE
    end
    digits << digit(q)
    digits.join
  end

  def digit(value)
    value < 26 ? ('a'.ord + value).chr : ('0'.ord + value - 26).chr
  end

  # adapts the bias after each encoded delta
  def adapt(delta, points, first)
    delta = first ? delta / DAMP : delta / 2
    delta += delta / points
    k = 0
    while delta > ((BASE - TMIN) * TMAX) / 2
      delta /= BASE - TMIN
      k += BASE
    end
    k + (((BASE - TMIN + 1) * delta) / (delta + SKEW))
  end
end
