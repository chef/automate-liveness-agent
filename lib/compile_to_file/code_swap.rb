module CompileToFile

  class CodeSwapNotFound < StandardError
  end

  class CodeSwap

    attr_reader :original
    attr_reader :replacement

    def initialize
      @original, @replacement = "", ""
      yield self if block_given?
    end

    def replace(original)
      @original = original
      self
    end

    def with(replacement)
      @replacement = replacement
    end

    def apply_to!(code, path)
      unless code.include?(original)
        message = "Could not find code to swap in #{path}\n"
        message << "The code to replace was:\n----\n"
        message << original
        message << "\n----\n"
        message << "The file contains:\n----\n"
        message << code
        message << "\n----\n"
        raise CodeSwapNotFound, message
      end
      code.gsub!(original, replacement)
    end

  end
end

