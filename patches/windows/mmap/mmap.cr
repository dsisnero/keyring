module Mmap
  PAGE_SIZE = 4096

  class Error < Exception; end
  class Closed < Error; end

  @[Flags]
  enum Prot
    None      = 0
    Read      = 1
    Write     = 2
    ReadWrite = 3
    Exec      = 4
  end

  @[Flags]
  enum Flags
    Fixed     = 0x10
    Huge      = 0
    Huge_2mb  = 0
    Huge_1gb  = 0
    CryptoKey = 0
    GuardPage = 0
  end

  abstract class View
    getter? closed = false

    def readwrite; end
    def readonly; end
    def noaccess; end

    def guard_page : Nil
      mprotect Prot::None
    end

    def crypto_key : Nil
    end

    def mprotect(prot : Prot) : Nil; end
    def msync : Nil; end
  end

  class Region < View
    def initialize(size : Int, flags = nil, *, prot : Prot = Prot::ReadWrite, shared = false, file = nil, offset = 0, addr = nil)
    end

    def [](idx : Int, size : Int) : SubRegion
      SubRegion.new(parent: self, offset: idx.to_i64, size: size)
    end

    def close; end
  end

  class SubRegion < View
    getter parent : View
    getter offset : Int64
    getter size : Int32

    def initialize(*, @parent : View, @offset : Int64, @size : Int32)
    end

    def [](idx : Int, size : Int) : SubRegion
      SubRegion.new(parent: self, offset: @offset + idx, size: size)
    end
  end
end
