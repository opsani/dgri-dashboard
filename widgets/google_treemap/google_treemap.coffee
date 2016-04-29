class Dashing.GoogleTreemap extends Dashing.Widget

  ready: ->
    container = $(@node).parent()
  # Gross hacks. Let's fix this.
    width = (Dashing.widget_base_dimensions[0] * container.data("sizex")) + Dashing.widget_margins[0] * 2 * (container.data("sizex"))
    height = (Dashing.widget_base_dimensions[1] * container.data("sizey"))

    console.log(width)
    console.log(height)
    colors = null
    if @get('colors')
      colors = @get('colors').split(/\s*,\s*/)

    @chart = new google.visualization.TreeMap($(@node).find(".chart")[0])
    @options =
      height: height,
      width: 300,
      highlightOnMouseOver: true,
      maxDepth: 1,
      maxPostDepth: 2,
      minHighlightColor: '#8c6bb1',
      midHighlightColor: '#9ebcda',
      maxHighlightColor: '#edf8fb',
      minColor: '#0098CB',
      maxColor: '#007ECD',
      headerHeight: 30,
      showScale: false,
      fontSize: 16,
      headerColor: '#12b0c5',
      useWeightedAverageForAggregation: true

    if @get('items')
      @data = google.visualization.arrayToDataTable @get('items')
    else
      @data = google.visualization.arrayToDataTable []

    @chart.draw @data, @options

  onData: (data) ->
    if @chart
      @data = google.visualization.arrayToDataTable data.items
      @chart.draw @data, @options
