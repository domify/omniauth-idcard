# -*- encoding: utf-8 -*-
$:.push File.expand_path("../lib", __FILE__)
require "omniauth-idcard/version"

Gem::Specification.new do |s|
  s.name        = "omniauth-idcard"
  s.version     = Omniauth::Idcard::VERSION
  s.authors     = ["Tarmo Talu"]
  s.email       = ["tarmo.talu@gmail.com"]
  s.homepage    = "http://github.com/tarmotalu/omniauth-idcard"
  s.summary     = %q{OmniAuth strategy for Estonian ID-Card}
  s.description = %q{OmniAuth strategy for Estonian ID-Card}

  s.rubyforge_project = "omniauth-idcard"

  s.files         = `git ls-files`.split("\n")
  s.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  s.executables   = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  s.require_paths = ["lib"]

  s.add_dependency 'omniauth-oauth'
  
  s.add_development_dependency 'rspec', '~> 2.12.0'
  s.add_development_dependency 'webmock'
  s.add_development_dependency 'simplecov'
  s.add_development_dependency 'rack-test'  
end
