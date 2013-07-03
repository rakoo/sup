# Monkey patch to inprove the output of Set's to_s so we can see what is inside
# the set.
class Set
  def to_s
    to_a.to_s
  end
end

