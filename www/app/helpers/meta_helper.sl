# Title, description and share image of every page. The data lives in
# config/pages.json so that scripts/og/build.sh can read it too and draw
# public/og/<key>.png: change a page there, then run the script.
#
# Read per call, not into a top-level const: a helper file's consts are not
# visible from the views that call its functions (they read as nil).

# The page's entry, plus "image", its share image under public/. A key without
# an entry gets the home page's text and image.
def page_meta(key)
    pages = JSON.parse(File.read("config/pages.json"))
    found = pages[key].nil? ? "home" : key
    meta = pages[found]
    meta["image"] = "og/" + found + ".png"
    meta
end

def site_url()
    "https://es.solisoft.net"
end
